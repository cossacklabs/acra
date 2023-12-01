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

package postgresql

import (
	"context"
	"errors"

	pg_query "github.com/Zhaars/pg_query_go/v4"
	"github.com/sirupsen/logrus"

	decryptor "github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/logging"
)

// ErrUpdateLeaveDataUnchanged show that data wasn't changed in UpdateExpressionValue with updateFunc
var ErrUpdateLeaveDataUnchanged = errors.New("updateFunc didn't change data")

// QueryDataEncryptor parse query and encrypt raw data according to TableSchemaStore
type QueryDataEncryptor struct {
	schemaStore         config.TableSchemaStore
	encryptor           base.DataEncryptor
	dataCoder           *PostgresqlPgQueryDBDataCoder
	querySelectSettings []*base.QueryDataItem
}

// NewQueryEncryptor create QueryDataEncryptor with DBDataCoder
func NewQueryEncryptor(schema config.TableSchemaStore, dataEncryptor base.DataEncryptor) (*QueryDataEncryptor, error) {
	return &QueryDataEncryptor{schemaStore: schema, encryptor: dataEncryptor, dataCoder: &PostgresqlPgQueryDBDataCoder{}}, nil
}

// ID returns name of this QueryObserver.
func (encryptor *QueryDataEncryptor) ID() string {
	return "QueryDataEncryptor"
}

// GetQueryEncryptionSettings returns collected in OnQuery callback encryptor settings
func (encryptor *QueryDataEncryptor) GetQueryEncryptionSettings() []*base.QueryDataItem {
	return encryptor.querySelectSettings
}

// encryptInsertQuery encrypt data in insert query in VALUES and ON DUPLICATE KEY UPDATE statements
func (encryptor *QueryDataEncryptor) encryptInsertQuery(ctx context.Context, insert *pg_query.InsertStmt, bindPlaceholders map[int]config.ColumnEncryptionSetting) (bool, error) {
	tableName := insert.Relation.GetRelname()
	schema := encryptor.schemaStore.GetTableSchema(tableName)
	if schema == nil {
		// unsupported table, we have not schema and query hasn't columns description
		logrus.Debugf("Hasn't schema for table %s", tableName)
		return false, nil
	}

	if encryptor.encryptor == nil && len(insert.ReturningList) > 0 {
		return false, encryptor.onReturning(ctx, insert.ReturningList, []*pg_query.Node{{
			Node: &pg_query.Node_RangeVar{
				RangeVar: insert.GetRelation(),
			},
		}})
	}

	var columnsName []string
	if len(insert.Cols) > 0 {
		columnsName = make([]string, 0, len(insert.Cols))
		for _, col := range insert.Cols {
			columnsName = append(columnsName, col.GetResTarget().Name)
		}
	} else if cols := schema.Columns(); len(cols) > 0 {
		columnsName = cols
	}

	changed := false

	if len(columnsName) > 0 {
		if insert.SelectStmt.GetSelectStmt() != nil {
			if valuesList := insert.SelectStmt.GetSelectStmt().GetValuesLists(); len(valuesList) > 0 {
				for _, listItem := range valuesList {
					// collect values per column
					items := listItem.GetList().GetItems()
					// in case when query `INSERT INTO table1 (col1, col2) VALUES (1, 2), (3, 4, 5);
					// in a tuple has incorrect amount of values ("5" in the example)
					if len(items) != len(columnsName) {
						continue
					}

					for j, value := range items {
						columnName := columnsName[j]
						expr := value.GetAConst()
						if value.GetTypeCast() != nil {
							expr = value.GetTypeCast().GetArg().GetAConst()
						}

						if changedValue, err := encryptor.encryptExpression(ctx, expr, schema, columnName, bindPlaceholders); err != nil {
							logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorEncryptorCantEncryptExpression).WithError(err).Errorln("Can't encrypt expression")
							return changed, err
						} else if changedValue {
							changed = true
						}
					}
				}
			}
		}
	}

	//	if len(insert.OnDup) > 0 {
	//		onDupChanged, err := encryptor.encryptUpdateExpressions(
	//			ctx,
	//			sqlparser.UpdateExprs(insert.OnDup),
	//			insert.Table,
	//			base.AliasToTableMap{insert.Table.Name.String(): insert.Table.Name.String()},
	//			bindPlaceholders)
	//		if err != nil {
	//			return changed, err
	//		}
	//		changed = changed || onDupChanged
	//	}

	return changed, nil
}

// encryptExpression check that expr is SQLVal and has Hexval then try to encrypt
func (encryptor *QueryDataEncryptor) encryptExpression(ctx context.Context, expr *pg_query.A_Const, schema config.TableSchema, columnName string, bindPlaceholder map[int]config.ColumnEncryptionSetting) (bool, error) {
	if schema.NeedToEncrypt(columnName) {
		setting := schema.GetColumnEncryptionSettings(columnName)
		//if sqlVal, ok := expr.(*sqlparser.SQLVal); ok {
		//	placeholderIndex, err := base.ParsePlaceholderIndex(sqlVal)
		//	if err == nil {
		//		bindPlaceholder[placeholderIndex] = setting
		//	}
		//}
		err := UpdateExpressionValue(ctx, expr, encryptor.dataCoder, setting, func(ctx context.Context, data []byte) ([]byte, error) {
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

// hasTablesToEncrypt check that exists schema for any table in tables
func (encryptor *QueryDataEncryptor) hasTablesToEncrypt(tables []*AliasedTableName) bool {
	for _, table := range tables {
		if v := encryptor.schemaStore.GetTableSchema(table.TableName); v != nil {
			return true
		}
	}
	return false
}

// encryptUpdateExpressions try to encrypt all supported exprs. Use firstTable if column has not explicit table name because it's implicitly used in DBMSs
func (encryptor *QueryDataEncryptor) encryptUpdateExpressions(ctx context.Context, updateExpr *pg_query.UpdateStmt, firstTable string, qualifierMap AliasToTableMap, bindPlaceholders map[int]config.ColumnEncryptionSetting) (bool, error) {
	var schema config.TableSchema
	var columnName string
	var changed bool

	for _, expr := range updateExpr.TargetList {
		// recognize table name of column
		resTarget := expr.GetResTarget()
		if len(resTarget.GetIndirection()) == 0 {
			schema = encryptor.schemaStore.GetTableSchema(firstTable)
			columnName = resTarget.GetName()
		} else {
			tableName := qualifierMap[resTarget.GetName()]
			schema = encryptor.schemaStore.GetTableSchema(tableName)
			columnName = resTarget.GetIndirection()[0].GetString_().GetSval()
		}
		if schema == nil {
			continue
		}

		aConst := resTarget.GetVal().GetAConst()
		if resTarget.GetVal().GetTypeCast() != nil {
			aConst = resTarget.GetVal().GetTypeCast().GetArg().GetAConst()
		}

		if changedExpr, err := encryptor.encryptExpression(ctx, aConst, schema, columnName, bindPlaceholders); err != nil {
			logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorEncryptorCantEncryptExpression).WithError(err).Errorln("Can't update expression with encrypted sql value")
			return changed, err
		} else if changedExpr {
			changed = true
		}
	}
	return changed, nil
}

// encryptUpdateQuery encrypt data in Update query and return true if any fields was encrypted, false if wasn't and error if error occurred
func (encryptor *QueryDataEncryptor) encryptUpdateQuery(ctx context.Context, update *pg_query.UpdateStmt, bindPlaceholders map[int]config.ColumnEncryptionSetting) (bool, error) {
	if update.GetRelation() == nil {
		return false, nil
	}

	tables := make([]*AliasedTableName, 0)

	var alias string
	if aliasRef := update.GetRelation().GetAlias(); aliasRef != nil {
		alias = aliasRef.GetAliasname()
	}
	tables = append(tables, &AliasedTableName{
		TableName: update.GetRelation().GetRelname(),
		As:        alias,
	})

	tables = append(tables, GetTablesWithAliases(update.FromClause)...)
	if !encryptor.hasTablesToEncrypt(tables) {
		return false, nil
	}

	qualifierMap := NewAliasToTableMapFromTables(tables)
	firstTable := tables[0].TableName

	// MySQL/MariaDB don`t support returning after update statements
	// Postgres doest but expect only one table in tables expression, but also can have more tables in FROM statement
	if encryptor.encryptor == nil && len(update.ReturningList) > 0 {
		return false, encryptor.onReturning(ctx, update.ReturningList, append(update.FromClause, &pg_query.Node{
			Node: &pg_query.Node_RangeVar{
				RangeVar: update.GetRelation(),
			},
		}))
	}

	return encryptor.encryptUpdateExpressions(ctx, update, firstTable, qualifierMap, bindPlaceholders)
}

// OnColumn return new encryption setting context if info exist, otherwise column data and passed context will be returned
func (encryptor *QueryDataEncryptor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	columnInfo, ok := decryptor.ColumnInfoFromContext(ctx)
	if ok {
		// return context with encryption setting
		if columnInfo.Index() < len(encryptor.querySelectSettings) {
			selectSetting := encryptor.querySelectSettings[columnInfo.Index()]
			if selectSetting != nil {

				logging.GetLoggerFromContext(ctx).WithField("column_index", columnInfo.Index()).WithField("column", selectSetting.ColumnName()).Debugln("Set encryption setting")
				return base.NewContextWithEncryptionSetting(ctx, selectSetting.Setting()), data, nil
			}
		}

	}
	return ctx, data, nil
}

func (encryptor *QueryDataEncryptor) onSelect(ctx context.Context, statement *pg_query.SelectStmt) (bool, error) {
	querySelectSettings, err := ParseQuerySettings(ctx, statement, encryptor.schemaStore)
	if err != nil {
		return false, err
	}
	//
	clientSession := decryptor.ClientSessionFromContext(ctx)
	base.SaveQueryDataItemsToClientSession(clientSession, querySelectSettings)

	encryptor.querySelectSettings = querySelectSettings
	return false, nil
}

func (encryptor *QueryDataEncryptor) onDelete(ctx context.Context, delete *pg_query.DeleteStmt) (bool, error) {
	if delete.GetRelation() == nil {
		return false, nil
	}

	tables := make([]*AliasedTableName, 0)

	var alias string
	if aliasRef := delete.GetRelation().GetAlias(); aliasRef != nil {
		alias = aliasRef.GetAliasname()
	}
	tables = append(tables, &AliasedTableName{
		TableName: delete.GetRelation().GetRelname(),
		As:        alias,
	})

	if len(delete.UsingClause) > 0 {
		tables = append(tables, GetTablesWithAliases(delete.UsingClause)...)
	}

	if !encryptor.hasTablesToEncrypt(tables) {
		return false, nil
	}

	if encryptor.encryptor == nil && len(delete.ReturningList) > 0 {
		return false, encryptor.onReturning(ctx, delete.ReturningList, append(delete.UsingClause, &pg_query.Node{
			Node: &pg_query.Node_RangeVar{
				RangeVar: delete.GetRelation(),
			},
		}))
	}

	return false, nil
}

func (encryptor *QueryDataEncryptor) onReturning(ctx context.Context, returning []*pg_query.Node, fromTables []*pg_query.Node) error {
	if len(returning) == 0 {
		return nil
	}

	querySelectSettings := make([]*base.QueryDataItem, 0, 8)

	for _, item := range returning {
		resTarget := item.GetResTarget()
		if resTarget == nil || resTarget.GetVal() == nil || resTarget.GetVal().GetColumnRef() == nil {
			querySelectSettings = append(querySelectSettings, nil)
			continue
		}

		fields := resTarget.GetVal().GetColumnRef().GetFields()
		if len(fields) == 0 {
			return nil
		}

		// returning t3.* => len(fields) == 2; fields[0] is t3 and fields[1] is GetAStar()
		// returning * => len(fields) == 1 => GetAStar()
		column := fields[0]
		if len(fields) > 1 {
			column = fields[1]
		}

		if column.GetAStar() != nil {
			for _, table := range fromTables {
				if table.GetRangeVar() == nil {
					return nil
				}

				tableName := table.GetRangeVar().GetRelname()
				// if the Returning is star and we have more than one table in the query e.g.
				// update table1 set did = tt.did from table2 as tt returning *
				// and the table is not in the encryptor config we cant collect corresponding querySettings as we dont actual table representation
				tableSchema := encryptor.schemaStore.GetTableSchema(tableName)
				if tableSchema == nil {
					logrus.WithField("table", tableName).Info("Unable to collect querySettings for table not in encryptor config")
					return errors.New("error to collect settings for unknown table")
				}

				for _, name := range tableSchema.Columns() {
					if columnSetting := tableSchema.GetColumnEncryptionSettings(name); columnSetting != nil {
						querySelectSettings = append(querySelectSettings, base.NewQueryDataItem(columnSetting, tableName, name, ""))
						continue
					}
					querySelectSettings = append(querySelectSettings, nil)
				}
			}
		}

		if column.GetString_() != nil {
			columnInfo, err := FindColumnInfo(fromTables, resTarget.GetVal().GetColumnRef(), encryptor.schemaStore)
			if err != nil {
				querySelectSettings = append(querySelectSettings, nil)
				continue
			}

			tableSchema := encryptor.schemaStore.GetTableSchema(columnInfo.Table)

			if columnSetting := tableSchema.GetColumnEncryptionSettings(columnInfo.Name); columnSetting != nil {
				querySelectSettings = append(querySelectSettings, base.NewQueryDataItem(columnSetting, columnInfo.Table, columnInfo.Name, ""))
				continue
			}
			querySelectSettings = append(querySelectSettings, nil)
		}
	}
	clientSession := decryptor.ClientSessionFromContext(ctx)
	base.SaveQueryDataItemsToClientSession(clientSession, querySelectSettings)
	encryptor.querySelectSettings = querySelectSettings
	return nil
}

// OnQuery raw data in query according to TableSchemaStore
func (encryptor *QueryDataEncryptor) OnQuery(ctx context.Context, query OnQueryObject) (OnQueryObject, bool, error) {
	encryptor.querySelectSettings = nil
	parseResult, err := query.Statement()
	if err != nil || len(parseResult.Stmts) == 0 {
		logrus.Debugln("Failed to parse incoming query", err)
		return query, false, nil
	}

	changed := false
	//collect placeholder in queries to save for future ParameterDescription packet to replace according to
	//setting's data type
	clientSession := decryptor.ClientSessionFromContext(ctx)
	bindPlaceholders := base.PlaceholderSettingsFromClientSession(clientSession)
	switch {
	case parseResult.Stmts[0].Stmt.GetSelectStmt() != nil:
		changed, err = encryptor.onSelect(ctx, parseResult.Stmts[0].Stmt.GetSelectStmt())
	case parseResult.Stmts[0].Stmt.GetInsertStmt() != nil:
		changed, err = encryptor.encryptInsertQuery(ctx, parseResult.Stmts[0].Stmt.GetInsertStmt(), bindPlaceholders)
	case parseResult.Stmts[0].Stmt.GetUpdateStmt() != nil:
		changed, err = encryptor.encryptUpdateQuery(ctx, parseResult.Stmts[0].Stmt.GetUpdateStmt(), bindPlaceholders)
	case parseResult.Stmts[0].Stmt.GetDeleteStmt() != nil:
		changed, err = encryptor.onDelete(ctx, parseResult.Stmts[0].Stmt.GetDeleteStmt())
	}
	if err != nil {
		return query, false, err
	}

	if changed {
		return NewOnQueryObjectFromStatement(parseResult), true, nil
	}
	return query, false, nil
}

// OnBind process bound values for prepared statement based on TableSchemaStore.
func (encryptor *QueryDataEncryptor) OnBind(ctx context.Context, parseResult *pg_query.ParseResult, values []decryptor.BoundValue) ([]decryptor.BoundValue, bool, error) {
	if encryptor.encryptor == nil {
		return values, false, nil
	}
	var newValues = values
	var changed bool
	var err error

	switch {
	case parseResult.Stmts[0].Stmt.GetInsertStmt() != nil:
		newValues, changed, err = encryptor.encryptInsertValues(ctx, parseResult.Stmts[0].Stmt.GetInsertStmt(), values)
	case parseResult.Stmts[0].Stmt.GetUpdateStmt() != nil:
		newValues, changed, err = encryptor.encryptUpdateValues(ctx, parseResult.Stmts[0].Stmt.GetUpdateStmt(), values)
	case parseResult.Stmts[0].Stmt.GetDeleteStmt() != nil:
		changed, err = encryptor.onDelete(ctx, parseResult.Stmts[0].Stmt.GetDeleteStmt())
	}

	if err != nil {
		return values, false, err
	}
	return newValues, changed, nil
}

func (encryptor *QueryDataEncryptor) getInsertPlaceholders(ctx context.Context, insert *pg_query.InsertStmt) (map[int]string, error) {
	tableName := insert.GetRelation().GetRelname()
	logger := logging.GetLoggerFromContext(ctx)
	// Look for the schema of the table where the INSERT happens.
	// If we don't have a schema then we don't know what to encrypt, so do nothing.
	schema := encryptor.schemaStore.GetTableSchema(tableName)
	if schema == nil {
		logger.WithField("table", tableName).Debugln("No encryption schema")
		return nil, nil
	}

	// Gather column names from the INSERT query. If there are no columns in the query,
	// expect a complete list of colums to be available in the schema.
	var columns []string
	if len(insert.GetCols()) > 0 {
		columns = make([]string, len(insert.GetCols()))
		for i, column := range insert.GetCols() {
			if column.GetResTarget() == nil {
				continue
			}

			columns[i] = column.GetResTarget().GetName()
		}
	} else if cols := schema.Columns(); len(cols) > 0 {
		columns = cols
	}
	// If there is no column schema available, we can't encrypt values.
	if len(columns) == 0 {
		logger.WithField("table", tableName).Debugln("No column information")
		return nil, nil
	}

	placeholders := make(map[int]string, len(insert.GetCols()))

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
	for _, list := range insert.SelectStmt.GetSelectStmt().GetValuesLists() {
		values := list.GetList().GetItems()
		valuesCount += len(values)
		for i, value := range values {
			if i >= len(columns) {
				logger.WithFields(logrus.Fields{"value_index": i, "column_count": len(columns)}).Warningln("Amount of values in INSERT bigger than column count")
				continue
			}
			err := encryptor.updatePlaceholderMap(valuesCount, placeholders, int(value.GetParamRef().GetNumber()), columns[i])
			if err != nil {
				return nil, err
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
	clientSession := decryptor.ClientSessionFromContext(ctx)
	bindData := base.PlaceholderSettingsFromClientSession(clientSession)
	for i, columnName := range placeholders {
		if !schema.NeedToEncrypt(columnName) {
			continue
		}
		setting := schema.GetColumnEncryptionSettings(columnName)
		bindData[i] = setting
	}
}

func (encryptor *QueryDataEncryptor) encryptInsertValues(ctx context.Context, insert *pg_query.InsertStmt, values []decryptor.BoundValue) ([]decryptor.BoundValue, bool, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Debugln("QueryDataEncryptor.encryptInsertValues")
	tableName := insert.GetRelation().GetRelname()
	// Look for the schema of the table where the INSERT happens.
	// If we don't have a schema then we don't know what to encrypt, so do nothing.
	schema := encryptor.schemaStore.GetTableSchema(tableName)
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
	//if len(insert.OnDup) > 0 {
	//	logrus.Warning("ON DUPLICATE KEY UPDATE is not supported in prepared statements")
	//}

	// Now that we know the placeholder mapping,
	// encrypt the values inserted into encrypted columns.
	return encryptor.encryptValuesWithPlaceholders(ctx, values, placeholders, schema)
}

func (encryptor *QueryDataEncryptor) encryptUpdateValues(ctx context.Context, update *pg_query.UpdateStmt, values []decryptor.BoundValue) ([]decryptor.BoundValue, bool, error) {
	logrus.Debugln("QueryDataEncryptor.encryptUpdateValues")
	// Get all tables involved in UPDATE with their aliases.
	// Column names in the queries might refer to the updated table in a different manner:
	//
	//     UPDATE table AS tbl SET tbl.col1 = $1, table.col2 = $2, `tbl2.col3` = $3 FROM tbl2 ...
	//
	// and we need to take all of that into account. But we're interested only in the first table.
	// If the updated table does not have a schema entry, there is nothing to encrypt here.
	tableName := update.GetRelation().GetRelname()
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
	for _, target := range update.TargetList {
		if target.GetResTarget() == nil {
			continue
		}

		columnName := target.GetResTarget().GetName()
		index := int(target.GetResTarget().GetVal().GetParamRef().GetNumber())
		err := encryptor.updatePlaceholderMap(len(values), placeholders, index, columnName)
		if err != nil {
			return values, false, err
		}
	}

	// Now that we know the placeholder mapping,
	// encrypt the values set into encrypted columns.
	return encryptor.encryptValuesWithPlaceholders(ctx, values, placeholders, schema)
}

// updatePlaceholderMap matches the placeholder of a value to its column and records this into the mapping.
func (encryptor *QueryDataEncryptor) updatePlaceholderMap(valuesCount int, placeholders map[int]string, index int, columnName string) error {
	// Placeholders use 1-based indexing and "values" (Go slice) are 0-based.
	index--
	if index >= valuesCount {
		logrus.WithFields(logrus.Fields{"placeholder": columnName, "index": index, "values": valuesCount}).
			Warning("Invalid placeholder index")
		return base.ErrInvalidPlaceholder
	}
	// Placeholders must map to columns uniquely.
	// If there is already a column for given placeholder and it's not the same,
	// we can't handle such queries currently.
	name, exists := placeholders[index]
	if exists && name != columnName {
		logrus.WithFields(logrus.Fields{"placeholder": columnName, "old_column": name, "new_column": columnName}).
			Warning("Inconsistent placeholder mapping")
		return base.ErrInconsistentPlaceholder
	}
	placeholders[index] = columnName
	return nil
}

// encryptValuesWithPlaceholders encrypts "values" of prepared statement parameters
// using the placeholder mapping which specifies the column which each value is mapped onto.
// If the database schema says that a column needs encryption, corresponding value is encrypted.
func (encryptor *QueryDataEncryptor) encryptValuesWithPlaceholders(ctx context.Context, values []decryptor.BoundValue, placeholders map[int]string, schema config.TableSchema) ([]decryptor.BoundValue, bool, error) {
	changed := false
	oldValues := make([]decryptor.BoundValue, len(values))
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
			values = make([]decryptor.BoundValue, len(oldValues))
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

// encryptWithColumnSettings encrypt data and use ClientID from ColumnEncryptionSetting if not empty otherwise static ClientID that passed to parser
func (encryptor *QueryDataEncryptor) encryptWithColumnSettings(ctx context.Context, columnSetting config.ColumnEncryptionSetting, data []byte) ([]byte, error) {
	logger := logrus.WithFields(logrus.Fields{"column": columnSetting.ColumnName()})
	logger.Debugln("QueryDataEncryptor.encryptWithColumnSettings")
	accessContext := decryptor.AccessContextFromContext(ctx)
	clientID := columnSetting.ClientID()
	if len(clientID) > 0 {
		logger.WithField("client_id", string(clientID)).Debugln("Encrypt with specific ClientID for column")
	} else {
		logger.WithField("client_id", string(accessContext.GetClientID())).Debugln("Encrypt with ClientID from connection")
		clientID = accessContext.GetClientID()
	}
	return encryptor.encryptor.EncryptWithClientID(clientID, data, columnSetting)
}
