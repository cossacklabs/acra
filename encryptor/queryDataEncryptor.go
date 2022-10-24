/*
Copyright 2018, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package encryptor

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
)

// QueryDataItem stores information about table column and encryption setting
type QueryDataItem struct {
	setting     config.ColumnEncryptionSetting
	tableName   string
	columnName  string
	columnAlias string
}

// Setting return associated ColumnEncryptionSetting or nil if not found
func (q *QueryDataItem) Setting() config.ColumnEncryptionSetting {
	return q.setting
}

// TableName return table name associated with item or empty string if it is not related to any table, or not recognized
func (q *QueryDataItem) TableName() string {
	return q.tableName
}

// ColumnName return column name if it was matched to any
func (q *QueryDataItem) ColumnName() string {
	return q.columnName
}

// ColumnAlias if matched as alias to any data item
func (q *QueryDataItem) ColumnAlias() string {
	return q.columnAlias
}

// QueryDataEncryptor parse query and encrypt raw data according to TableSchemaStore
type QueryDataEncryptor struct {
	schemaStore         config.TableSchemaStore
	encryptor           DataEncryptor
	dataCoder           DBDataCoder
	querySelectSettings []*QueryDataItem
	parser              *sqlparser.Parser
}

// NewMysqlQueryEncryptor create QueryDataEncryptor with MySQLDBDataCoder
func NewMysqlQueryEncryptor(schema config.TableSchemaStore, parser *sqlparser.Parser, dataEncryptor DataEncryptor) (*QueryDataEncryptor, error) {
	return &QueryDataEncryptor{schemaStore: schema, parser: parser, encryptor: dataEncryptor, dataCoder: &MysqlDBDataCoder{}}, nil
}

// NewPostgresqlQueryEncryptor create QueryDataEncryptor with PostgresqlDBDataCoder
func NewPostgresqlQueryEncryptor(schema config.TableSchemaStore, parser *sqlparser.Parser, dataEncryptor DataEncryptor) (*QueryDataEncryptor, error) {
	return &QueryDataEncryptor{schemaStore: schema, parser: parser, encryptor: dataEncryptor, dataCoder: &PostgresqlDBDataCoder{}}, nil
}

// ID returns name of this QueryObserver.
func (encryptor *QueryDataEncryptor) ID() string {
	return "QueryDataEncryptor"
}

// encryptInsertQuery encrypt data in insert query in VALUES and ON DUPLICATE KEY UPDATE statements
func (encryptor *QueryDataEncryptor) encryptInsertQuery(ctx context.Context, insert *sqlparser.Insert, bindPlaceholders map[int]config.ColumnEncryptionSetting) (bool, error) {
	tableName := insert.Table.Name
	schema := encryptor.schemaStore.GetTableSchema(tableName.ValueForConfig())
	if schema == nil {
		// unsupported table, we have not schema and query hasn't columns description
		logrus.Debugf("Hasn't schema for table %s", tableName)
		return false, nil
	}

	if encryptor.encryptor == nil {
		return false, encryptor.onReturning(ctx, insert.Returning, tableName.ValueForConfig())
	}

	var columnsName []string
	if len(insert.Columns) > 0 {
		columnsName = make([]string, 0, len(insert.Columns))
		for _, col := range insert.Columns {
			columnsName = append(columnsName, col.ValueForConfig())
		}
	} else if cols := schema.Columns(); len(cols) > 0 {
		columnsName = cols
	}

	changed := false

	if len(columnsName) > 0 {
		switch rows := insert.Rows.(type) {
		case sqlparser.Values:
			for _, valTuple := range rows {
				// collect values per column
				for j, value := range valTuple {
					// in case when query `INSERT INTO table1 (col1, col2) VALUES (1, 2), (3, 4, 5);
					// in a tuple has incorrect amount of values ("5" in the example)
					if j >= len(columnsName) {
						continue
					}
					columnName := columnsName[j]
					if changedValue, err := encryptor.encryptExpression(ctx, value, schema, columnName, bindPlaceholders); err != nil {
						logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorEncryptorCantEncryptExpression).WithError(err).Errorln("Can't encrypt expression")
						return changed, err
					} else if changedValue {
						changed = true
					}
				}
			}
		}
	}

	if len(insert.OnDup) > 0 {
		onDupChanged, err := encryptor.encryptUpdateExpressions(
			ctx,
			sqlparser.UpdateExprs(insert.OnDup),
			insert.Table,
			AliasToTableMap{insert.Table.Name.String(): insert.Table.Name.String()},
			bindPlaceholders)
		if err != nil {
			return changed, err
		}
		changed = changed || onDupChanged
	}

	return changed, nil
}

// ErrUpdateLeaveDataUnchanged show that data wasn't changed in UpdateExpressionValue with updateFunc
var ErrUpdateLeaveDataUnchanged = errors.New("updateFunc didn't change data")

// UpdateExpressionValue decode value from DB related string to binary format, call updateFunc, encode to DB string format and replace value in expression with new
func UpdateExpressionValue(ctx context.Context, expr sqlparser.Expr, coder DBDataCoder, updateFunc func(context.Context, []byte) ([]byte, error)) error {
	switch val := expr.(type) {
	case *sqlparser.UnaryExpr:
		return UpdateUnaryExpressionValue(ctx, expr.(*sqlparser.UnaryExpr), coder, updateFunc)
	// Update Parenthese expression like  `('AAAA')` just by processing inner
	// expression 'AAAA'.
	case *sqlparser.ParenExpr:
		return UpdateExpressionValue(ctx, expr.(*sqlparser.ParenExpr).Expr, coder, updateFunc)
	case *sqlparser.SQLVal:
		switch val.Type {
		case sqlparser.StrVal, sqlparser.HexVal, sqlparser.PgEscapeString, sqlparser.IntVal, sqlparser.HexNum:
			rawData, err := coder.Decode(val)
			if err != nil {
				if err == utils.ErrDecodeOctalString || err == errUnsupportedExpression {
					logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeSQLValue).
						WithError(err).
						Warningln("Can't decode data with unsupported coding format or unsupported expression")
					return ErrUpdateLeaveDataUnchanged
				}
				return err
			}

			newData, err := updateFunc(ctx, rawData)
			if err != nil {
				return err
			}
			if len(newData) == len(rawData) && bytes.Equal(newData, rawData) {
				return ErrUpdateLeaveDataUnchanged
			}
			coded, err := coder.Encode(expr, newData)
			if err != nil {
				return err
			}
			val.Val = coded
		}
	}
	return nil
}

// UpdateUnaryExpressionValue updates supported unary expression
// By now, supported are only `_binary` charsets, that are parsed as unary expr.
func UpdateUnaryExpressionValue(ctx context.Context, expr *sqlparser.UnaryExpr, coder DBDataCoder, updateFunc func(context.Context, []byte) ([]byte, error)) error {
	switch unaryVal := expr.Expr.(type) {
	case *sqlparser.SQLVal:
		switch strings.TrimSpace(expr.Operator) {
		case "_binary":
			return UpdateExpressionValue(ctx, unaryVal, coder, updateFunc)
		}
	}
	return nil
}

// encryptExpression check that expr is SQLVal and has Hexval then try to encrypt
func (encryptor *QueryDataEncryptor) encryptExpression(ctx context.Context, expr sqlparser.Expr, schema config.TableSchema, columnName string, bindPlaceholder map[int]config.ColumnEncryptionSetting) (bool, error) {
	if schema.NeedToEncrypt(columnName) {
		if sqlVal, ok := expr.(*sqlparser.SQLVal); ok {
			placeholderIndex, err := ParsePlaceholderIndex(sqlVal)
			if err == nil {
				setting := schema.GetColumnEncryptionSettings(columnName)
				bindPlaceholder[placeholderIndex] = setting
			}
		}
		err := UpdateExpressionValue(ctx, expr, encryptor.dataCoder, func(ctx context.Context, data []byte) ([]byte, error) {
			if len(data) == 0 {
				return data, nil
			}
			return encryptor.encryptWithColumnSettings(ctx, schema.GetColumnEncryptionSettings(columnName), data)
		})
		// didn't change anything because it already encrypted
		if err == ErrUpdateLeaveDataUnchanged {
			return false, nil
		} else if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// AliasedTableName store TableName and related As value together
type AliasedTableName struct {
	TableName sqlparser.TableName
	As        sqlparser.TableIdent
}

// GetTablesWithAliases collect all tables from all update TableExprs which may be as subquery/table/join/etc
// collect only table names and ignore aliases for subqueries
func GetTablesWithAliases(tables sqlparser.TableExprs) []*AliasedTableName {
	var outputTables []*AliasedTableName
	for _, tableExpr := range tables {
		switch statement := tableExpr.(type) {
		case *sqlparser.AliasedTableExpr:
			aliasedStatement := statement.Expr.(sqlparser.SimpleTableExpr)
			switch simpleTableStatement := aliasedStatement.(type) {
			case sqlparser.TableName:
				outputTables = append(outputTables, &AliasedTableName{TableName: simpleTableStatement, As: statement.As})
			case *sqlparser.Subquery:
				// unsupported
			default:
				logrus.Debugf("Unsupported SimpleTableExpr type %s", reflect.TypeOf(simpleTableStatement))
			}
		case *sqlparser.ParenTableExpr:
			outputTables = append(outputTables, GetTablesWithAliases(statement.Exprs)...)
		case *sqlparser.JoinTableExpr:
			outputTables = append(outputTables, GetTablesWithAliases(sqlparser.TableExprs{statement.LeftExpr, statement.RightExpr})...)
		default:
			logrus.Debugf("Unsupported TableExpr type %s", reflect.TypeOf(tableExpr))
		}
	}
	return outputTables
}

// hasTablesToEncrypt check that exists schema for any table in tables
func (encryptor *QueryDataEncryptor) hasTablesToEncrypt(tables []*AliasedTableName) bool {
	for _, table := range tables {
		if v := encryptor.schemaStore.GetTableSchema(table.TableName.Name.ValueForConfig()); v != nil {
			return true
		}
	}
	return false
}

// encryptUpdateExpressions try to encrypt all supported exprs. Use firstTable if column has not explicit table name because it's implicitly used in DBMSs
func (encryptor *QueryDataEncryptor) encryptUpdateExpressions(ctx context.Context, exprs sqlparser.UpdateExprs, firstTable sqlparser.TableName, qualifierMap AliasToTableMap, bindPlaceholders map[int]config.ColumnEncryptionSetting) (bool, error) {
	var schema config.TableSchema
	changed := false
	for _, expr := range exprs {
		// recognize table name of column
		if expr.Name.Qualifier.IsEmpty() {
			schema = encryptor.schemaStore.GetTableSchema(firstTable.Name.ValueForConfig())
		} else {
			tableName := qualifierMap[expr.Name.Qualifier.Name.String()]
			schema = encryptor.schemaStore.GetTableSchema(tableName)
		}
		if schema == nil {
			continue
		}
		columnName := expr.Name.Name.ValueForConfig()
		if changedExpr, err := encryptor.encryptExpression(ctx, expr.Expr, schema, columnName, bindPlaceholders); err != nil {
			logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorEncryptorCantEncryptExpression).WithError(err).Errorln("Can't update expression with encrypted sql value")
			return changed, err
		} else if changedExpr {
			changed = true
		}
	}
	return changed, nil
}

// AliasToTableMap store table alias as key and table name as value
type AliasToTableMap map[string]string

// NewAliasToTableMapFromTables create AliasToTableMap from slice of aliased tables
func NewAliasToTableMapFromTables(tables []*AliasedTableName) AliasToTableMap {
	qualifierMap := AliasToTableMap{}
	for _, table := range tables {
		if table.As.IsEmpty() {
			qualifierMap[table.TableName.Name.ValueForConfig()] = table.TableName.Name.ValueForConfig()
		} else {
			qualifierMap[table.As.ValueForConfig()] = table.TableName.Name.ValueForConfig()
		}
	}
	return qualifierMap
}

// encryptUpdateQuery encrypt data in Update query and return true if any fields was encrypted, false if wasn't and error if error occurred
func (encryptor *QueryDataEncryptor) encryptUpdateQuery(ctx context.Context, update *sqlparser.Update, bindPlaceholders map[int]config.ColumnEncryptionSetting) (bool, error) {
	tables := GetTablesWithAliases(update.TableExprs)
	if !encryptor.hasTablesToEncrypt(tables) {
		return false, nil
	}
	if len(tables) == 0 {
		return false, nil
	}
	qualifierMap := NewAliasToTableMapFromTables(tables)
	firstTable := tables[0].TableName
	return encryptor.encryptUpdateExpressions(ctx, update.Exprs, firstTable, qualifierMap, bindPlaceholders)
}

// OnColumn return new encryption setting context if info exist, otherwise column data and passed context will be returned
func (encryptor *QueryDataEncryptor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	columnInfo, ok := base.ColumnInfoFromContext(ctx)
	if ok {
		// return context with encryption setting
		if columnInfo.Index() < len(encryptor.querySelectSettings) {
			selectSetting := encryptor.querySelectSettings[columnInfo.Index()]
			if selectSetting != nil {

				logging.GetLoggerFromContext(ctx).WithField("column_index", columnInfo.Index()).WithField("column", selectSetting.ColumnName()).Debugln("Set encryption setting")
				return NewContextWithEncryptionSetting(ctx, selectSetting.Setting()), data, nil
			}
		}

	}
	return ctx, data, nil
}

const allColumnsName = "*"

func (encryptor *QueryDataEncryptor) onSelect(ctx context.Context, statement *sqlparser.Select) (bool, error) {
	columns, err := mapColumnsToAliases(statement)
	if err != nil {
		logrus.WithError(err).Errorln("Can't extract columns from SELECT statement")
		return false, err
	}
	querySelectSettings := make([]*QueryDataItem, 0, len(columns))
	for _, data := range columns {
		if data != nil {
			if schema := encryptor.schemaStore.GetTableSchema(data.Table); schema != nil {
				var setting *QueryDataItem = nil
				if data.Name == allColumnsName {
					for _, name := range schema.Columns() {
						setting = nil
						if columnSetting := schema.GetColumnEncryptionSettings(name); columnSetting != nil {
							setting = &QueryDataItem{
								setting:     columnSetting,
								tableName:   data.Table,
								columnName:  name,
								columnAlias: "",
							}
						}
						querySelectSettings = append(querySelectSettings, setting)
					}
				} else {
					if columnSetting := schema.GetColumnEncryptionSettings(data.Name); columnSetting != nil {
						setting = &QueryDataItem{
							setting:     columnSetting,
							tableName:   data.Table,
							columnName:  data.Name,
							columnAlias: data.Alias,
						}
					}
					querySelectSettings = append(querySelectSettings, setting)
				}
				continue
			}
		}
		querySelectSettings = append(querySelectSettings, nil)
	}
	clientSession := base.ClientSessionFromContext(ctx)
	SaveQueryDataItemsToClientSession(clientSession, querySelectSettings)

	encryptor.querySelectSettings = querySelectSettings
	return false, nil
}

func (encryptor *QueryDataEncryptor) onReturning(ctx context.Context, returning sqlparser.Returning, tableName string) error {
	if len(returning) == 0 {
		return nil
	}

	schema := encryptor.schemaStore.GetTableSchema(tableName)
	querySelectSettings := make([]*QueryDataItem, 0, 8)

	if _, ok := returning[0].(*sqlparser.StarExpr); ok {
		for _, name := range schema.Columns() {
			if columnSetting := schema.GetColumnEncryptionSettings(name); columnSetting != nil {
				querySelectSettings = append(querySelectSettings, &QueryDataItem{
					setting:    columnSetting,
					tableName:  tableName,
					columnName: name,
				})
				continue
			}
			querySelectSettings = append(querySelectSettings, nil)
		}
		clientSession := base.ClientSessionFromContext(ctx)
		SaveQueryDataItemsToClientSession(clientSession, querySelectSettings)
		encryptor.querySelectSettings = querySelectSettings
		return nil
	}

	for _, item := range returning {
		var colName *sqlparser.ColName
		switch returningItem := item.(type) {
		case *sqlparser.AliasedExpr:
			switch expr := returningItem.Expr.(type) {
			case *sqlparser.ColName:
				colName = expr
				break
			default:
				// skip all other not relevant types
				querySelectSettings = append(querySelectSettings, nil)
				continue
			}
		default:
			// skip all other not relevant types: StarExpr & Nextval
			querySelectSettings = append(querySelectSettings, nil)
			continue
		}
		rawColName := colName.Name.String()
		if columnSetting := schema.GetColumnEncryptionSettings(rawColName); columnSetting != nil {
			querySelectSettings = append(querySelectSettings, &QueryDataItem{
				setting:    columnSetting,
				tableName:  tableName,
				columnName: rawColName,
			})
			continue
		}
		querySelectSettings = append(querySelectSettings, nil)
	}
	clientSession := base.ClientSessionFromContext(ctx)
	SaveQueryDataItemsToClientSession(clientSession, querySelectSettings)
	encryptor.querySelectSettings = querySelectSettings
	return nil
}

// OnQuery raw data in query according to TableSchemaStore
func (encryptor *QueryDataEncryptor) OnQuery(ctx context.Context, query base.OnQueryObject) (base.OnQueryObject, bool, error) {
	statement, err := query.Statement()
	if err != nil {
		return query, false, err
	}
	changed := false
	// collect placeholder in queries to save for future ParameterDescription packet to replace according to
	// setting's data type
	clientSession := base.ClientSessionFromContext(ctx)
	bindPlaceholders := PlaceholderSettingsFromClientSession(clientSession)
	switch typedStatement := statement.(type) {
	case *sqlparser.Select:
		changed, err = encryptor.onSelect(ctx, typedStatement)
	case *sqlparser.Insert:
		changed, err = encryptor.encryptInsertQuery(ctx, typedStatement, bindPlaceholders)
	case *sqlparser.Update:
		if encryptor.encryptor != nil {
			changed, err = encryptor.encryptUpdateQuery(ctx, typedStatement, bindPlaceholders)
		}
	}
	if err != nil {
		return query, false, err
	}
	if changed {
		return base.NewOnQueryObjectFromStatement(statement, encryptor.parser), true, nil
	}
	return query, false, nil
}

// ErrInvalidPlaceholder is returned when Acra cannot parse SQL placeholder expression.
var ErrInvalidPlaceholder = errors.New("invalid placeholder value")

// ErrInconsistentPlaceholder is returned when a placeholder refers to multiple different columns.
var ErrInconsistentPlaceholder = errors.New("inconsistent placeholder usage")

// OnBind process bound values for prepared statement based on TableSchemaStore.
func (encryptor *QueryDataEncryptor) OnBind(ctx context.Context, statement sqlparser.Statement, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	if encryptor.encryptor == nil {
		return values, false, nil
	}
	newValues := values
	changed := false
	var err error
	switch statement := statement.(type) {
	case *sqlparser.Insert:
		newValues, changed, err = encryptor.encryptInsertValues(ctx, statement, values)
	case *sqlparser.Update:
		newValues, changed, err = encryptor.encryptUpdateValues(ctx, statement, values)
	}
	if err != nil {
		return values, false, err
	}
	return newValues, changed, nil
}

func (encryptor *QueryDataEncryptor) getInsertPlaceholders(ctx context.Context, insert *sqlparser.Insert) (map[int]string, error) {
	tableName := insert.Table.Name
	logger := logging.GetLoggerFromContext(ctx)
	// Look for the schema of the table where the INSERT happens.
	// If we don't have a schema then we don't know what to encrypt, so do nothing.
	schema := encryptor.schemaStore.GetTableSchema(tableName.ValueForConfig())
	if schema == nil {
		logger.WithField("table", tableName).Debugln("No encryption schema")
		return nil, nil
	}

	// Gather column names from the INSERT query. If there are no columns in the query,
	// expect a complete list of colums to be available in the schema.
	var columns []string
	if len(insert.Columns) > 0 {
		columns = make([]string, len(insert.Columns))
		for i, column := range insert.Columns {
			columns[i] = column.String()
		}
	} else if cols := schema.Columns(); len(cols) > 0 {
		columns = cols
	}
	// If there is no column schema available, we can't encrypt values.
	if len(columns) == 0 {
		logger.WithField("table", tableName).Debugln("No column information")
		return nil, nil
	}

	placeholders := make(map[int]string, len(insert.Columns))

	// We can also only process simple queries of the form
	//
	//     INSERT INTO table(column...) VALUES ($1, $2, 'static value'...);
	//
	// That is, where placeholders uniquely identify the column and used directly
	// as inserted values. We don't support functions, casts, inserting query results, etc.
	//
	// Walk through the query to find out which placeholders stand for which columns.
	// Also count amount of passed value to validate that placeholder's index doesn't go out of this number
	valuesCount := 0
	switch rows := insert.Rows.(type) {
	case sqlparser.Values:
		for _, row := range rows {
			valuesCount += len(row)
			for i, value := range row {
				if i >= len(columns) {
					logger.WithFields(logrus.Fields{"value_index": i, "column_count": len(columns)}).Warningln("Amount of values in INSERT bigger than column count")
					continue
				}
				switch value := value.(type) {
				case *sqlparser.SQLVal:
					err := encryptor.updatePlaceholderMap(valuesCount, placeholders, value, columns[i])
					if err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return placeholders, nil
}

func (encryptor *QueryDataEncryptor) savePlaceholderSettingIntoClientSession(ctx context.Context, placeholders map[int]string, schema config.TableSchema) {
	if schema == nil {
		logrus.Debugln("No encryption schema")
		return
	}
	if placeholders == nil {
		logrus.Debugln("No placeholders")
		return
	}
	clientSession := base.ClientSessionFromContext(ctx)
	bindData := PlaceholderSettingsFromClientSession(clientSession)
	for i, columnName := range placeholders {
		if !schema.NeedToEncrypt(columnName) {
			continue
		}
		setting := schema.GetColumnEncryptionSettings(columnName)
		bindData[i] = setting
	}
}

func (encryptor *QueryDataEncryptor) encryptInsertValues(ctx context.Context, insert *sqlparser.Insert, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Debugln("QueryDataEncryptor.encryptInsertValues")
	tableName := insert.Table.Name
	// Look for the schema of the table where the INSERT happens.
	// If we don't have a schema then we don't know what to encrypt, so do nothing.
	schema := encryptor.schemaStore.GetTableSchema(tableName.ValueForConfig())
	if schema == nil {
		logrus.WithField("table", tableName).Debugln("No encryption schema")
		return values, false, nil
	}
	placeholders, err := encryptor.getInsertPlaceholders(ctx, insert)
	if err != nil {
		logger.WithError(err).Errorln("Can't extract placeholders from INSERT query")
		return values, false, err
	}
	encryptor.savePlaceholderSettingIntoClientSession(ctx, placeholders, schema)

	// TODO(ilammy, 2020-10-13): handle ON DUPLICATE KEY UPDATE clauses
	// These clauses are handled for textual queries. It would be nice to encrypt
	// any prepared statement parameters that are used there as well.
	// See "encryptInsertQuery" for reference.
	if len(insert.OnDup) > 0 {
		logrus.Warning("ON DUPLICATE KEY UPDATE is not supported in prepared statements")
	}

	// Now that we know the placeholder mapping,
	// encrypt the values inserted into encrypted columns.
	return encryptor.encryptValuesWithPlaceholders(ctx, values, placeholders, schema)
}

func (encryptor *QueryDataEncryptor) encryptUpdateValues(ctx context.Context, update *sqlparser.Update, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	logrus.Debugln("QueryDataEncryptor.encryptUpdateValues")
	// Get all tables involved in UPDATE with their aliases.
	// Column names in the queries might refer to the updated table in a different manner:
	//
	//     UPDATE table AS tbl SET tbl.col1 = $1, table.col2 = $2, `tbl2.col3` = $3 FROM tbl2 ...
	//
	// and we need to take all of that into account. But we're interested only in the first table.
	// If the updated table does not have a schema entry, there is nothing to encrypt here.
	tables := GetTablesWithAliases(update.TableExprs)
	//tableName := tables[0].TableName.Name.String()
	tableName := tables[0].TableName.Name.ValueForConfig()
	schema := encryptor.schemaStore.GetTableSchema(tableName)
	if schema == nil {
		logrus.WithField("table", tableName).Debugln("No encryption schema")
		return values, false, nil
	}

	placeholders := make(map[int]string, len(values))

	// We can only process simple queries of the form
	//
	//     UPDATE table SET column1 = $1, column2 = $2, column3 = 'static value' ...
	//
	// That is, where placeholders uniquely identify the column and used directly
	// as new values. We don't support functions, casts, updating tables based o
	// query results, etc.
	//
	// Walk through SET clauses to find out which placeholders stand for which columns.
	for _, expr := range update.Exprs {
		columnName := expr.Name.Name.String()
		switch value := expr.Expr.(type) {
		case *sqlparser.SQLVal:
			err := encryptor.updatePlaceholderMap(len(values), placeholders, value, columnName)
			if err != nil {
				return values, false, err
			}
		}
	}

	// Now that we know the placeholder mapping,
	// encrypt the values set into encrypted columns.
	return encryptor.encryptValuesWithPlaceholders(ctx, values, placeholders, schema)
}

// updatePlaceholderMap matches the placeholder of a value to its column and records this into the mapping.
func (encryptor *QueryDataEncryptor) updatePlaceholderMap(valuesCount int, placeholders map[int]string, placeholder *sqlparser.SQLVal, columnName string) error {
	updateMapByPlaceholderPart := func(part string) error {
		text := string(placeholder.Val)
		index, err := strconv.Atoi(strings.TrimPrefix(text, part))
		if err != nil {
			logrus.WithField("placeholder", text).WithError(err).Warning("Cannot parse placeholder")
			return err
		}
		// Placeholders use 1-based indexing and "values" (Go slice) are 0-based.
		index--
		if index >= valuesCount {
			logrus.WithFields(logrus.Fields{"placeholder": text, "index": index, "values": valuesCount}).
				Warning("Invalid placeholder index")
			return ErrInvalidPlaceholder
		}
		// Placeholders must map to columns uniquely.
		// If there is already a column for given placeholder and it's not the same,
		// we can't handle such queries currently.
		name, exists := placeholders[index]
		if exists && name != columnName {
			logrus.WithFields(logrus.Fields{"placeholder": text, "old_column": name, "new_column": columnName}).
				Warning("Inconsistent placeholder mapping")
			return ErrInconsistentPlaceholder
		}
		placeholders[index] = columnName
		return nil
	}

	switch placeholder.Type {
	case sqlparser.ValArg:
		// MySQL placeholders look like ":v1". Parse the number out of them.
		return updateMapByPlaceholderPart(":v")

	case sqlparser.PgPlaceholder:
		// PostgreSQL placeholders look like "$1". Parse the number out of them.
		return updateMapByPlaceholderPart("$")
	}
	return nil
}

// encryptValuesWithPlaceholders encrypts "values" of prepared statement parameters
// using the placeholder mapping which specifies the column which each value is mapped onto.
// If the database schema says that a column needs encryption, corresponding value is encrypted.
func (encryptor *QueryDataEncryptor) encryptValuesWithPlaceholders(ctx context.Context, values []base.BoundValue, placeholders map[int]string, schema config.TableSchema) ([]base.BoundValue, bool, error) {
	changed := false
	oldValues := make([]base.BoundValue, len(values))
	for index, value := range values {
		oldValues[index] = value.Copy()
	}

	for valueIndex, columnName := range placeholders {
		if !schema.NeedToEncrypt(columnName) {
			continue
		}

		// Allocate the result slice only if there are some values that need encryption.
		// Otherwise we'll just return the original old one.
		if !changed {
			values = make([]base.BoundValue, len(oldValues))
			copy(values, oldValues)
		}
		changed = true
		setting := schema.GetColumnEncryptionSettings(columnName)
		valueData, err := values[valueIndex].GetData(setting)
		if err != nil {
			return nil, false, err
		}
		if len(valueData) == 0 {
			continue
		}
		encryptedData, err := encryptor.encryptWithColumnSettings(ctx, setting, valueData)
		if err != nil && err != ErrUpdateLeaveDataUnchanged {
			logrus.WithError(err).WithFields(logrus.Fields{"index": valueIndex, "column": columnName}).
				Debug("Failed to encrypt column")
			return oldValues, false, err
		}

		err = values[valueIndex].SetData(encryptedData, setting)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{"index": valueIndex, "column": columnName}).
				Debug("Failed to set encrypted value")
			return nil, false, err
		}
	}

	return values, changed, nil
}

// encryptWithColumnSettings encrypt data and use ZoneId or ClientID from ColumnEncryptionSetting if not empty otherwise static ClientID that passed to parser
func (encryptor *QueryDataEncryptor) encryptWithColumnSettings(ctx context.Context, columnSetting config.ColumnEncryptionSetting, data []byte) ([]byte, error) {
	logger := logrus.WithFields(logrus.Fields{"column": columnSetting.ColumnName()})
	logger.Debugln("QueryDataEncryptor.encryptWithColumnSettings")
	zoneID := columnSetting.ZoneID()
	if len(zoneID) > 0 {
		logger.WithField("zone_id", string(zoneID)).Debugln("Encrypt with specific ZoneID for column")
		return encryptor.encryptor.EncryptWithZoneID(zoneID, data, columnSetting)
	}
	accessContext := base.AccessContextFromContext(ctx)
	clientID := columnSetting.ClientID()
	if len(clientID) > 0 {
		logger.WithField("client_id", string(clientID)).Debugln("Encrypt with specific ClientID for column")
	} else {
		logger.WithField("client_id", string(accessContext.GetClientID())).Debugln("Encrypt with ClientID from connection")
		clientID = accessContext.GetClientID()
	}
	return encryptor.encryptor.EncryptWithClientID(clientID, data, columnSetting)
}
