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

type querySelectSetting struct {
	setting     config.ColumnEncryptionSetting
	tableName   string
	columnName  string
	columnAlias string
}

// QueryDataEncryptor parse query and encrypt raw data according to TableSchemaStore
type QueryDataEncryptor struct {
	schemaStore         config.TableSchemaStore
	encryptor           DataEncryptor
	clientID            []byte
	dataCoder           DBDataCoder
	querySelectSettings []*querySelectSetting
}

// NewMysqlQueryEncryptor create QueryDataEncryptor with MySQLDBDataCoder
func NewMysqlQueryEncryptor(schema config.TableSchemaStore, clientID []byte, dataEncryptor DataEncryptor) (*QueryDataEncryptor, error) {
	return &QueryDataEncryptor{schemaStore: schema, clientID: clientID, encryptor: dataEncryptor, dataCoder: &MysqlDBDataCoder{}}, nil
}

// NewPostgresqlQueryEncryptor create QueryDataEncryptor with PostgresqlDBDataCoder
func NewPostgresqlQueryEncryptor(schema config.TableSchemaStore, clientID []byte, dataEncryptor DataEncryptor) (*QueryDataEncryptor, error) {
	return &QueryDataEncryptor{schemaStore: schema, clientID: clientID, encryptor: dataEncryptor, dataCoder: &PostgresqlDBDataCoder{}}, nil
}

// ID returns name of this QueryObserver.
func (encryptor *QueryDataEncryptor) ID() string {
	return "QueryDataEncryptor"
}

// encryptInsertQuery encrypt data in insert query in VALUES and ON DUPLICATE KEY UPDATE statements
func (encryptor *QueryDataEncryptor) encryptInsertQuery(insert *sqlparser.Insert) (bool, error) {
	tableName := insert.Table.Name
	schema := encryptor.schemaStore.GetTableSchema(tableName.String())
	if schema == nil {
		// unsupported table, we have not schema and query hasn't columns description
		logrus.Debugf("Hasn't schema for table %s", tableName)
		return false, nil
	}

	var columnsName []string
	if len(insert.Columns) > 0 {
		columnsName = make([]string, 0, len(insert.Columns))
		for _, col := range insert.Columns {
			columnsName = append(columnsName, col.String())
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
					columnName := columnsName[j]
					if changedValue, err := encryptor.encryptExpression(value, schema, columnName); err != nil {
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
		onDupChanged, err := encryptor.encryptUpdateExpressions(sqlparser.UpdateExprs(insert.OnDup), insert.Table, AliasToTableMap{insert.Table.Name.String(): insert.Table.Name.String()})
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
func UpdateExpressionValue(expr sqlparser.Expr, coder DBDataCoder, updateFunc func([]byte) ([]byte, error)) error {
	switch val := expr.(type) {
	case *sqlparser.SQLVal:
		switch val.Type {
		case sqlparser.StrVal, sqlparser.HexVal, sqlparser.PgEscapeString, sqlparser.IntVal:
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

			newData, err := updateFunc(rawData)
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

// encryptExpression check that expr is SQLVal and has Hexval then try to encrypt
func (encryptor *QueryDataEncryptor) encryptExpression(expr sqlparser.Expr, schema config.TableSchema, columnName string) (bool, error) {
	if schema.NeedToEncrypt(columnName) {
		err := UpdateExpressionValue(expr, encryptor.dataCoder, func(data []byte) ([]byte, error) {
			if len(data) == 0 {
				return data, nil
			}
			return encryptor.encryptWithColumnSettings(schema.GetColumnEncryptionSettings(columnName), data)
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
		if v := encryptor.schemaStore.GetTableSchema(table.TableName.Name.String()); v != nil {
			return true
		}
	}
	return false
}

// encryptUpdateExpressions try to encrypt all supported exprs. Use firstTable if column has not explicit table name because it's implicitly used in DBMSs
func (encryptor *QueryDataEncryptor) encryptUpdateExpressions(exprs sqlparser.UpdateExprs, firstTable sqlparser.TableName, qualifierMap AliasToTableMap) (bool, error) {
	var schema config.TableSchema
	changed := false
	for _, expr := range exprs {
		// recognize table name of column
		if expr.Name.Qualifier.IsEmpty() {
			schema = encryptor.schemaStore.GetTableSchema(firstTable.Name.String())
		} else {
			tableName := qualifierMap[expr.Name.Qualifier.Name.String()]
			schema = encryptor.schemaStore.GetTableSchema(tableName)
		}
		if schema == nil {
			continue
		}
		columnName := expr.Name.Name.String()
		if changedExpr, err := encryptor.encryptExpression(expr.Expr, schema, columnName); err != nil {
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
			qualifierMap[table.TableName.Name.String()] = table.TableName.Name.String()
		} else {
			qualifierMap[table.As.String()] = table.TableName.Name.String()
		}
	}
	return qualifierMap
}

// encryptUpdateQuery encrypt data in Update query and return true if any fields was encrypted, false if wasn't and error if error occurred
func (encryptor *QueryDataEncryptor) encryptUpdateQuery(update *sqlparser.Update) (bool, error) {
	tables := GetTablesWithAliases(update.TableExprs)
	if !encryptor.hasTablesToEncrypt(tables) {
		return false, nil
	}
	if len(tables) == 0 {
		return false, nil
	}
	qualifierMap := NewAliasToTableMapFromTables(tables)
	firstTable := tables[0].TableName
	return encryptor.encryptUpdateExpressions(update.Exprs, firstTable, qualifierMap)
}

func (encryptor *QueryDataEncryptor) onSelect(statement *sqlparser.Select) (bool, error) {
	columns := mapColumnsToAliases(statement)
	querySelectSettings := make([]*querySelectSetting, 0, len(columns))
	for _, data := range columns {
		if data != nil {
			if schema := encryptor.schemaStore.GetTableSchema(data.Table); schema != nil {
				if columnSetting := schema.GetColumnEncryptionSettings(data.Name); columnSetting != nil {
					querySelectSettings = append(querySelectSettings, &querySelectSetting{
						setting:     columnSetting,
						tableName:   data.Table,
						columnName:  data.Name,
						columnAlias: data.Alias,
					})
					continue
				}
			}
		}
		querySelectSettings = append(querySelectSettings, nil)
	}
	encryptor.querySelectSettings = querySelectSettings
	return false, nil
}

// OnQuery raw data in query according to TableSchemaStore
func (encryptor *QueryDataEncryptor) OnQuery(query base.OnQueryObject) (base.OnQueryObject, bool, error) {
	statement, err := query.Statement()
	if err != nil {
		return query, false, err
	}
	changed := false
	switch statement := statement.(type) {
	case *sqlparser.Select:
		changed, err = encryptor.onSelect(statement)
	case *sqlparser.Insert:
		changed, err = encryptor.encryptInsertQuery(statement)
	case *sqlparser.Update:
		changed, err = encryptor.encryptUpdateQuery(statement)
	}
	if err != nil {
		return query, false, err
	}
	if changed {
		return base.NewOnQueryObjectFromStatement(statement), true, nil
	}
	return query, false, nil
}

// ErrInvalidPlaceholder is returned when Acra cannot parse SQL placeholder expression.
var ErrInvalidPlaceholder = errors.New("invalid placeholder value")

// ErrInconsistentPlaceholder is returned when a placeholder refers to multiple different columns.
var ErrInconsistentPlaceholder = errors.New("inconsistent placeholder usage")

// OnBind process bound values for prepared statement based on TableSchemaStore.
func (encryptor *QueryDataEncryptor) OnBind(statement sqlparser.Statement, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	newValues := values
	changed := false
	var err error
	switch statement := statement.(type) {
	case *sqlparser.Insert:
		newValues, changed, err = encryptor.encryptInsertValues(statement, values)
	case *sqlparser.Update:
		newValues, changed, err = encryptor.encryptUpdateValues(statement, values)
	}
	if err != nil {
		return values, false, err
	}
	return newValues, changed, nil
}

func (encryptor *QueryDataEncryptor) encryptInsertValues(insert *sqlparser.Insert, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	logrus.Debugln("QueryDataEncryptor.encryptInsertValues")
	tableName := insert.Table.Name
	// Look for the schema of the table where the INSERT happens.
	// If we don't have a schema then we don't know what to encrypt, so do nothing.
	schema := encryptor.schemaStore.GetTableSchema(tableName.String())
	if schema == nil {
		logrus.WithField("table", tableName).Debugln("No encryption schema")
		return values, false, nil
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
		logrus.WithField("table", tableName).Debugln("No column information")
		return values, false, nil
	}

	placeholders := make(map[int]string, len(values))

	// We can also only process simple queries of the form
	//
	//     INSERT INTO table(column...) VALUES ($1, $2, 'static value'...);
	//
	// That is, where placeholders uniquely identify the column and used directly
	// as inserted values. We don't support functions, casts, inserting query results, etc.
	//
	// Walk through the query to find out which placeholders stand for which columns.
	switch rows := insert.Rows.(type) {
	case sqlparser.Values:
		for _, row := range rows {
			for i, value := range row {
				switch value := value.(type) {
				case *sqlparser.SQLVal:
					err := encryptor.updatePlaceholderMap(values, placeholders, value, columns[i])
					if err != nil {
						return values, false, err
					}
				}
			}
		}
	}

	// TODO(ilammy, 2020-10-13): handle ON DUPLICATE KEY UPDATE clauses
	// These clauses are handled for textual queries. It would be nice to encrypt
	// any prepared statement parameters that are used there as well.
	// See "encryptInsertQuery" for reference.
	if len(insert.OnDup) > 0 {
		logrus.Warning("ON DUPLICATE KEY UPDATE is not supported in prepared statements")
	}

	// Now that we know the placeholder mapping,
	// encrypt the values inserted into encrypted columns.
	return encryptor.encryptValuesWithPlaceholders(values, placeholders, schema)
}

func (encryptor *QueryDataEncryptor) encryptUpdateValues(update *sqlparser.Update, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	logrus.Debugln("QueryDataEncryptor.encryptUpdateValues")
	// Get all tables involved in UPDATE with their aliases.
	// Column names in the queries might refer to the updated table in a different manner:
	//
	//     UPDATE table AS tbl SET tbl.col1 = $1, table.col2 = $2, `tbl2.col3` = $3 FROM tbl2 ...
	//
	// and we need to take all of that into account. But we're interested only in the first table.
	// If the updated table does not have a schema entry, there is nothing to encrypt here.
	tables := GetTablesWithAliases(update.TableExprs)
	tableName := tables[0].TableName.Name.String()
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
			err := encryptor.updatePlaceholderMap(values, placeholders, value, columnName)
			if err != nil {
				return values, false, err
			}
		}
	}

	// Now that we know the placeholder mapping,
	// encrypt the values set into encrypted columns.
	return encryptor.encryptValuesWithPlaceholders(values, placeholders, schema)
}

// updatePlaceholderMap matches the placeholder of a value to its column and records this into the mapping.
func (encryptor *QueryDataEncryptor) updatePlaceholderMap(values []base.BoundValue, placeholders map[int]string, placeholder *sqlparser.SQLVal, columnName string) error {
	// TODO(ilammy, 2020-10-15): handle MySQL placeholders too
	// MySQL placeholders do not contain indices, you just need to count them
	// and sequentially assign to values and columns.
	switch placeholder.Type {
	case sqlparser.PgPlaceholder:
		// PostgreSQL placeholders look like "$1". Parse the number out of them.
		text := string(placeholder.Val)
		index, err := strconv.Atoi(strings.TrimPrefix(text, "$"))
		if err != nil {
			logrus.WithField("placeholder", text).WithError(err).Warning("Cannot parse placeholder")
			return err
		}
		// Placeholders use 1-based indexing and "values" (Go slice) are 0-based.
		index--
		if index >= len(values) {
			logrus.WithFields(logrus.Fields{"placeholder": text, "index": index, "values": len(values)}).
				Warning("Invalid placeholder index")
			return ErrInvalidPlaceholder
		}
		// Placeholders must map to columns uniquely.
		// If there is already a column for given placholder and it's not the same,
		// we can't handle such queries currently.
		name, exists := placeholders[index]
		if exists && name != columnName {
			logrus.WithFields(logrus.Fields{"placeholder": text, "old_column": name, "new_column": columnName}).
				Warning("Inconsistent placeholder mapping")
			return ErrInconsistentPlaceholder
		}
		placeholders[index] = columnName
	default:
		// Not a placeholder at all, ignore it.
	}
	return nil
}

// encryptValuesWithPlaceholders encrypts "values" of prepared statement parameters
// using the placeholder mapping which specifies the column which each value is mapped onto.
// If the database schema says that a column needs encryption, corresponding value is encrypted.
func (encryptor *QueryDataEncryptor) encryptValuesWithPlaceholders(values []base.BoundValue, placeholders map[int]string, schema config.TableSchema) ([]base.BoundValue, bool, error) {
	changed := false
	oldValues := values

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

		settings := schema.GetColumnEncryptionSettings(columnName)
		format := values[valueIndex].Format()
		data := values[valueIndex].Data()
		switch format {
		case base.BinaryFormat:
			encryptedData, err := encryptor.encryptWithColumnSettings(settings, data)
			// If the data turns out to be already encrypted then it's fatal. Otherwise, bail out.
			if err != nil && err != ErrUpdateLeaveDataUnchanged {
				logrus.WithError(err).WithFields(logrus.Fields{"index": valueIndex, "column": columnName}).
					Debug("Failed to encrypt column")
				return oldValues, false, err
			}
			values[valueIndex] = base.NewBoundValue(encryptedData, base.BinaryFormat)

		// TODO(ilammy, 2020-10-14): implement support for base.TextFormat
		// We should parse and decode the data, encrypt it, and then either force binary format,
		// or reencode the data back into text.

		default:
			logrus.WithFields(logrus.Fields{"format": format, "index": valueIndex, "column": columnName}).
				Warning("Parameter format not supported, skipping")
		}
	}

	return values, changed, nil
}

// encryptWithColumnSettings encrypt data and use ZoneId or ClientID from ColumnEncryptionSetting if not empty otherwise static ClientID that passed to parser
func (encryptor *QueryDataEncryptor) encryptWithColumnSettings(columnSetting config.ColumnEncryptionSetting, data []byte) ([]byte, error) {
	logger := logrus.WithFields(logrus.Fields{"column": columnSetting.ColumnName()})
	logger.Debugln("QueryDataEncryptor.encryptWithColumnSettings")
	zoneID := columnSetting.ZoneID()
	if len(zoneID) > 0 {
		logger.WithField("zone_id", string(zoneID)).Debugln("Encrypt with specific ZoneID for column")
		return encryptor.encryptor.EncryptWithZoneID(zoneID, data, columnSetting)
	}
	clientID := columnSetting.ClientID()
	if len(clientID) > 0 {
		logger.WithField("client_id", string(clientID)).Debugln("Encrypt with specific ClientID for column")
	} else {
		logger.WithField("client_id", string(encryptor.clientID)).Debugln("Encrypt with ClientID from connection")
		clientID = encryptor.clientID
	}
	return encryptor.encryptor.EncryptWithClientID(clientID, data, columnSetting)
}
