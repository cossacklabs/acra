/*
Copyright 2019, Cossack Labs Limited

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
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/sqlparser"
)

var (
	errNotFoundtable          = errors.New("not found table for alias")
	errNotSupported           = errors.New("not supported type of sql node")
	errTableAlreadyMatched    = errors.New("aliased table name already matched")
	errAliasedTableNotMatched = errors.New("aliases table not matched")
)

type columnInfo struct {
	Name  string
	Table string
	Alias string
}

var errEmptyTableExprs = errors.New("empty table exprs")

// parseJoinTablesInfo recursively read and save sql join structure info, aliases map is used to save association between tables and its aliases,
// tables slice is used to collect certain order of tables (saved in reverse order of declaration).
// JoinTableExpr structure represent a recursive tree where RightExpr and LeftExpr are corresponded leaf node
// recursive processing starts from RightExpr leaf to the LeftExpr one, and when cast LeftExpr to AliasedTableExpr is successful
// it means that we reach last leaf in the tree.
func parseJoinTablesInfo(joinExp *sqlparser.JoinTableExpr, tables *[]string, aliases map[string]string) bool {
	aliased, ok := joinExp.LeftExpr.(*sqlparser.AliasedTableExpr)
	if ok {
		// here we reach the last leaf in the JoinTableExpr recursive tree, processing SHOULD be stopped in this block.
		// and we should process remaining RightExpr and LeftExpr leafs more before exit.
		ok := getRightJoinTableInfo(joinExp, tables, aliases)
		if !ok {
			return false
		}

		_, ok = aliased.Expr.(*sqlparser.Subquery)
		if ok {
			//  add subquery processing if needed
			return true
		}

		tableName, ok := aliased.Expr.(sqlparser.TableName)
		if !ok {
			return false
		}

		alias := aliased.As.RawValue()
		if aliased.As.RawValue() == "" {
			alias = tableName.Name.RawValue()
		}

		*tables = append(*tables, tableName.Name.RawValue())
		aliases[alias] = tableName.Name.RawValue()
		return true
	}

	ok = getRightJoinTableInfo(joinExp, tables, aliases)
	if !ok {
		return false
	}

	joinExp, ok = joinExp.LeftExpr.(*sqlparser.JoinTableExpr)
	if !ok {
		return false
	}

	return parseJoinTablesInfo(joinExp, tables, aliases)
}

// getRightJoinTableInfo return tableName and its alias for right join table
// in case of more complex JOINs constructions like `JOIN (table1 AS t1 JOIN table2 AS t2 ON ... JOIN table3 ...) ON ...`
// represented by sqlparser.ParenTableExpr it runs parseJoinTablesInfo itself recursively to collect tableName and its alias info inside this block
func getRightJoinTableInfo(joinExp *sqlparser.JoinTableExpr, tables *[]string, aliases map[string]string) bool {
	parentExpr, ok := joinExp.RightExpr.(*sqlparser.ParenTableExpr)
	if ok {
		for _, expr := range parentExpr.Exprs {
			innerJoinExpr, ok := expr.(*sqlparser.JoinTableExpr)
			if !ok {
				continue
			}
			return parseJoinTablesInfo(innerJoinExpr, tables, aliases)
		}
	}

	rAliased, ok := joinExp.RightExpr.(*sqlparser.AliasedTableExpr)
	if !ok {
		return false
	}

	tableName, ok := rAliased.Expr.(sqlparser.TableName)
	if !ok {
		return false
	}

	alias := rAliased.As.RawValue()
	if rAliased.As.RawValue() == "" {
		alias = tableName.Name.RawValue()
	}
	if _, ok := aliases[alias]; !ok {
		*tables = append(*tables, tableName.Name.RawValue())
		aliases[alias] = tableName.Name.RawValue()
	}

	return true
}

// getJoinFirstTableWithoutAlias recursively process JoinTableExpr tree until it reaches the first table in JOIN declarations
// used to handle queries like this `select table1.column1, column2, column3 from table1 join table2 as t2` and match column2 to table1
func getJoinFirstTableWithoutAlias(joinExp *sqlparser.JoinTableExpr) (string, bool) {
	aliased, ok := joinExp.LeftExpr.(*sqlparser.AliasedTableExpr)
	if ok {
		return getNonAliasedName(aliased)
	}

	joinExp, ok = joinExp.LeftExpr.(*sqlparser.JoinTableExpr)
	if !ok {
		return "", false
	}
	return getJoinFirstTableWithoutAlias(joinExp)
}

// getFirstTableWithoutAlias search table name from "FROM" expression which has not any alias
// if more than one table specified without alias then return errNotFoundTable
func getFirstTableWithoutAlias(fromExpr sqlparser.TableExprs) (string, error) {
	if len(fromExpr) == 0 {
		return "", errEmptyTableExprs
	}

	if joinExp, ok := fromExpr[0].(*sqlparser.JoinTableExpr); ok {
		tableName, ok := getJoinFirstTableWithoutAlias(joinExp)
		if !ok {
			return "", errNotFoundtable
		}
		return tableName, nil
	}

	var name string
	for _, tblExpr := range fromExpr {
		aliased, ok := tblExpr.(*sqlparser.AliasedTableExpr)
		if !ok {
			continue
		}
		tName, ok := getNonAliasedName(aliased)
		if !ok {
			continue
		}
		if name != "" {
			return "", errors.New("more than 1 table without alias")
		}
		name = tName
	}
	if name == "" {
		return "", errNotFoundtable
	}
	return name, nil
}

func findColumnInfo(fromExpr sqlparser.TableExprs, colName *sqlparser.ColName, schemaStore config.TableSchemaStore) (columnInfo, error) {
	var alias = colName.Qualifier.Name.RawValue()
	var columnName = colName.Name.ValueForConfig()

	if alias == "" {
		columnTable, err := getMatchedTable(fromExpr, colName, schemaStore)
		if err != nil {
			return columnInfo{}, err
		}
		alias = columnTable
	}

	info, err := findTableName(alias, columnName, fromExpr)
	if err != nil {
		return columnInfo{}, err
	}
	info.Alias = alias

	return info, nil
}

func getMatchedTable(fromExpr sqlparser.TableExprs, colName *sqlparser.ColName, tableSchemaStore config.TableSchemaStore) (string, error) {
	if len(fromExpr) == 0 {
		return "", errEmptyTableExprs
	}

	if joinExp, ok := fromExpr[0].(*sqlparser.JoinTableExpr); ok {
		tableName, ok := getJoinFirstTableWithoutAlias(joinExp)
		if !ok {
			return "", errNotFoundtable
		}
		return tableName, nil
	}

	isTableColumn := func(tableSchema config.TableSchema, colName *sqlparser.ColName) bool {
		for _, column := range tableSchema.Columns() {
			if column == colName.Name.ValueForConfig() {
				return true
			}
		}
		return false
	}

	var alisedName string
	for _, exp := range fromExpr {
		aliased, ok := exp.(*sqlparser.AliasedTableExpr)
		if !ok {
			continue
		}

		tableName, ok := aliased.Expr.(sqlparser.TableName)
		if !ok {
			return "", errUnsupportedExpression
		}

		tableSchema := tableSchemaStore.GetTableSchema(tableName.Name.ValueForConfig())
		if tableSchema == nil {
			continue
		}

		if isTableColumn(tableSchema, colName) {
			getTableName := getAliasedName
			if aliased.As.IsEmpty() {
				getTableName = getNonAliasedName
			}

			tName, ok := getTableName(aliased)
			if !ok {
				return "", errUnsupportedExpression
			}

			if alisedName != "" {
				logrus.WithField("alias", alisedName).Infoln("Ambiguous column found, several tables contain the same column")
				return "", errTableAlreadyMatched
			}

			alisedName = tName
		}
	}

	if alisedName == "" {
		return "", errAliasedTableNotMatched
	}

	return alisedName, nil
}

func getAliasedName(aliased *sqlparser.AliasedTableExpr) (string, bool) {
	if _, ok := aliased.Expr.(sqlparser.TableName); !ok {
		return "", false
	}

	if aliased.As.IsEmpty() {
		return "", false
	}

	return aliased.As.ValueForConfig(), true
}

func getNonAliasedName(aliased *sqlparser.AliasedTableExpr) (string, bool) {
	if !aliased.As.IsEmpty() {
		return "", false
	}
	tableName, ok := aliased.Expr.(sqlparser.TableName)
	if !ok {
		return "", false
	}
	return tableName.Name.ValueForConfig(), true
}

func getTableNameWithoutAliases(expr sqlparser.TableExpr) (string, error) {
	aliased, ok := expr.(*sqlparser.AliasedTableExpr)
	if !ok {
		return "", errNotFoundtable
	}
	tableName, ok := aliased.Expr.(sqlparser.TableName)
	if !ok {
		return "", errNotFoundtable
	}
	return tableName.Name.RawValue(), nil
}

func findTableName(alias, columnName string, expr sqlparser.SQLNode) (columnInfo, error) {
	switch val := expr.(type) {
	case sqlparser.TableExprs:
		// FROM table1, table2, join ....
		// search through list of tables by specific type of sql node (AliasedTableExpr, Join, ...)
		for _, tblExpr := range val {
			result, err := findTableName(alias, columnName, tblExpr)
			if err == nil {
				return result, nil
			}
		}
		return columnInfo{}, errNotFoundtable
	case sqlparser.TableName:
		// table1, should be equal to end alias value
		if alias == val.Name.ValueForConfig() {
			return columnInfo{Name: columnName, Table: alias}, nil
		}
		return columnInfo{}, errNotFoundtable
	case *sqlparser.AliasedTableExpr:
		if val.As.IsEmpty() {
			return findTableName(alias, columnName, val.Expr)
		}
		if val.As.RawValue() == alias {
			if tblName, ok := val.Expr.(sqlparser.TableName); ok {
				return findTableName(tblName.Name.ValueForConfig(), columnName, val.Expr)
			}
			return findTableName("", columnName, val.Expr)
		}
	case *sqlparser.Subquery:
		return findTableName(alias, columnName, val.Select)
	case *sqlparser.Select:
		for _, expr := range val.SelectExprs {
			if aliasExpr, ok := expr.(*sqlparser.AliasedExpr); ok {
				if aliasExpr.As.IsEmpty() {
					// select t1.col1
					switch aliasVal := aliasExpr.Expr.(type) {
					case *sqlparser.ColName:
						if aliasVal.Qualifier.IsEmpty() {
							// select col1
							if aliasVal.Name.EqualString(columnName) {
								// find first table in FROM list
								firstTable, err := getFirstTableWithoutAlias(val.From)
								if err != nil {
									continue
								}
								return columnInfo{Name: columnName, Table: firstTable}, nil
							}
						} else {
							// t1.col1 == col1 so we should find source name of t1.
							if aliasVal.Name.EqualString(columnName) {
								return findTableName(aliasVal.Qualifier.Name.RawValue(), aliasVal.Name.String(), val.From)
							}
						}
						continue
					}
				} else if aliasExpr.As.EqualString(alias) || (alias == "" && aliasExpr.As.EqualString(columnName)) {
					// select t1.col1 as columnName
					switch aliasVal := aliasExpr.Expr.(type) {
					case *sqlparser.ColName:
						if aliasVal.Qualifier.Name.RawValue() == "" {
							firstTable, err := getFirstTableWithoutAlias(val.From)
							if err != nil {
								return columnInfo{}, err
							}
							return findTableName(firstTable, aliasVal.Name.String(), val.From)
						}
						return findTableName(aliasVal.Qualifier.Name.RawValue(), aliasVal.Name.String(), val.From)
					}
				}
			}
		}
	case *sqlparser.JoinTableExpr:
		result, err := findTableName(alias, columnName, val.LeftExpr)
		if err == errNotFoundtable {
			return findTableName(alias, columnName, val.RightExpr)
		}
		return result, err
	case *sqlparser.Union:
		// may be different pairs of table + column at same position of result row
		return columnInfo{}, errNotSupported
	case *sqlparser.ParenSelect:
		return findTableName(alias, columnName, val.Select)
	case *sqlparser.ParenTableExpr:
		for _, exr := range val.Exprs {
			result, err := findTableName(alias, columnName, exr)
			if err == nil {
				return result, nil
			}
		}
		return columnInfo{}, errNotFoundtable
	}
	return columnInfo{}, errNotFoundtable
}

func mapColumnsToAliases(selectQuery *sqlparser.Select, tableSchemaStore config.TableSchemaStore) ([]*columnInfo, error) {
	out := make([]*columnInfo, 0, len(selectQuery.SelectExprs))
	var joinTables []string
	var joinAliases map[string]string

	if joinExp, ok := selectQuery.From[0].(*sqlparser.JoinTableExpr); ok {
		joinTables = make([]string, 0)
		joinAliases = make(map[string]string)

		if ok := parseJoinTablesInfo(joinExp, &joinTables, joinAliases); !ok {
			return nil, errUnsupportedExpression
		}
	}

	for _, expr := range selectQuery.SelectExprs {
		aliased, ok := expr.(*sqlparser.AliasedExpr)
		if ok {
			// processing queries like `select (select value from table2) from table1`
			// subquery should return only one value
			subQuery, ok := aliased.Expr.(*sqlparser.Subquery)
			if ok {
				if subSelect, ok := subQuery.Select.(*sqlparser.Select); ok {
					if len(subSelect.SelectExprs) != 1 {
						return nil, errUnsupportedExpression
					}

					if _, ok := subSelect.SelectExprs[0].(*sqlparser.StarExpr); ok {
						return nil, errUnsupportedExpression
					}

					subColumn, err := mapColumnsToAliases(subSelect, tableSchemaStore)
					if err != nil {
						return nil, err
					}
					out = append(out, subColumn...)
					continue
				}
			}

			colName, ok := aliased.Expr.(*sqlparser.ColName)
			if ok {
				info, err := findColumnInfo(selectQuery.From, colName, tableSchemaStore)
				if err == nil {
					out = append(out, &info)
					continue
				}
			}
		}
		starExpr, ok := expr.(*sqlparser.StarExpr)
		if ok {
			if len(joinTables) > 0 {
				if !starExpr.TableName.Name.IsEmpty() {
					joinTable, ok := joinAliases[starExpr.TableName.Name.ValueForConfig()]
					if !ok {
						return nil, errUnsupportedExpression
					}
					out = append(out, &columnInfo{Table: joinTable, Name: allColumnsName, Alias: allColumnsName})
					continue
				}

				for i := len(joinTables) - 1; i >= 0; i-- {
					out = append(out, &columnInfo{Table: joinTables[i], Name: allColumnsName, Alias: allColumnsName})
				}
				continue
			}

			tableName, err := getFirstTableWithoutAlias(selectQuery.From)
			if err == nil {
				out = append(out, &columnInfo{Table: tableName, Name: allColumnsName, Alias: allColumnsName})
			} else {
				if len(selectQuery.From) == 1 {
					tableNameStr, err := getTableNameWithoutAliases(selectQuery.From[0])
					if err != nil {
						return nil, err
					}
					out = append(out, &columnInfo{Table: tableNameStr, Name: allColumnsName, Alias: allColumnsName})
					continue
				}
				tableNameStr, err := findTableName(starExpr.TableName.Name.RawValue(), starExpr.TableName.Name.RawValue(), selectQuery.From)
				if err != nil {
					return nil, err
				}
				out = append(out, &columnInfo{Table: tableNameStr.Table, Name: allColumnsName, Alias: allColumnsName})
			}
			continue
		}
		out = append(out, nil)
	}
	return out, nil
}

// InvalidPlaceholderIndex value that represent invalid index for sql placeholders
const InvalidPlaceholderIndex = -1

// ParsePlaceholderIndex parse placeholder index if SQLVal is PgPlaceholder/ValArg otherwise return error and InvalidPlaceholderIndex
func ParsePlaceholderIndex(placeholder *sqlparser.SQLVal) (int, error) {
	updateMapByPlaceholderPart := func(part string) (int, error) {
		text := string(placeholder.Val)
		index, err := strconv.Atoi(strings.TrimPrefix(text, part))
		if err != nil {
			logrus.WithField("placeholder", text).WithError(err).Warning("Cannot parse placeholder")
			return InvalidPlaceholderIndex, err
		}
		// Placeholders use 1-based indexing and "values" (Go slice) are 0-based.
		index--
		return index, nil
	}

	switch placeholder.Type {
	case sqlparser.PgPlaceholder:
		// PostgreSQL placeholders look like "$1". Parse the number out of them.
		return updateMapByPlaceholderPart("$")
	case sqlparser.ValArg:
		// MySQL placeholders look like ":v1". Parse the number out of them.
		return updateMapByPlaceholderPart(":v")
	}
	return InvalidPlaceholderIndex, ErrInvalidPlaceholder
}

// ParseSearchQueryPlaceholdersSettings parse encryption settings of statement with placeholders
func ParseSearchQueryPlaceholdersSettings(statement sqlparser.Statement, schemaStore config.TableSchemaStore) map[int]config.ColumnEncryptionSetting {
	tableExps, err := filterTableExpressions(statement)
	if err != nil {
		logrus.Debugln("Unsupported search query")
		return nil
	}

	// Walk through WHERE clauses of a SELECT statements...
	whereExprs, err := getWhereStatements(statement)
	if err != nil {
		logrus.WithError(err).Debugln("Failed to extract WHERE clauses")
		return nil
	}

	placeHolderSettings := make(map[int]config.ColumnEncryptionSetting)
	for _, whereExpr := range whereExprs {
		err = sqlparser.Walk(func(node sqlparser.SQLNode) (kontinue bool, err error) {
			comparisonExpr, ok := node.(*sqlparser.ComparisonExpr)
			if !ok {
				return true, nil
			}

			var colName *sqlparser.ColName

			switch expr := comparisonExpr.Left.(type) {
			case *sqlparser.ColName:
				colName = expr
			case *sqlparser.SubstrExpr:
				colName = expr.Name
			}

			columnInfo, err := findColumnInfo(tableExps, colName, schemaStore)
			if err != nil {
				return true, nil
			}

			lColumnSetting := getColumnSetting(colName, columnInfo, schemaStore)
			if lColumnSetting == nil {
				return true, nil
			}

			if !lColumnSetting.IsSearchable() && !lColumnSetting.IsConsistentTokenization() {
				return true, nil
			}

			if sqlVal, ok := comparisonExpr.Right.(*sqlparser.SQLVal); ok && isSupportedSQLVal(sqlVal) {
				if comparisonExpr.Operator == sqlparser.EqualStr || comparisonExpr.Operator == sqlparser.NotEqualStr || comparisonExpr.Operator == sqlparser.NullSafeEqualStr {

					placeholderIndex, err := ParsePlaceholderIndex(sqlVal)
					if err == ErrInvalidPlaceholder {
						return true, nil
					} else if err != nil {
						return false, err
					}
					placeHolderSettings[placeholderIndex] = lColumnSetting
				}
			}

			return true, nil
		}, whereExpr)
	}

	return placeHolderSettings
}

const queryDataItemKey = "query_data_items"

// SaveQueryDataItemsToClientSession save slice of QueryDataItem into ClientSession
func SaveQueryDataItemsToClientSession(session base.ClientSession, items []*QueryDataItem) {
	session.SetData(queryDataItemKey, items)
}

// DeleteQueryDataItemsFromClientSession delete items from ClientSession
func DeleteQueryDataItemsFromClientSession(session base.ClientSession) {
	session.DeleteData(queryDataItemKey)
}

// QueryDataItemsFromClientSession return QueryDataItems from ClientSession if saved otherwise nil
func QueryDataItemsFromClientSession(session base.ClientSession) []*QueryDataItem {
	data, ok := session.GetData(queryDataItemKey)
	if !ok {
		return nil
	}
	items, ok := data.([]*QueryDataItem)
	if ok {
		return items
	}
	return nil
}

var bindPlaceholdersPool = sync.Pool{New: func() interface{} {
	return make(map[int]config.ColumnEncryptionSetting, 32)
}}

const placeholdersSettingKey = "bind_encryption_settings"

// PlaceholderSettingsFromClientSession return stored in client session ColumnEncryptionSettings related to placeholders
// or create new and save in session
func PlaceholderSettingsFromClientSession(session base.ClientSession) map[int]config.ColumnEncryptionSetting {
	data, ok := session.GetData(placeholdersSettingKey)
	if !ok {
		//logger := logging.GetLoggerFromContext(session.Context())
		value := bindPlaceholdersPool.Get().(map[int]config.ColumnEncryptionSetting)
		//logger.WithField("session", session).WithField("value", value).Debugln("Create placeholders")
		session.SetData(placeholdersSettingKey, value)
		return value
	}
	items, ok := data.(map[int]config.ColumnEncryptionSetting)
	if ok {
		return items
	}
	return nil
}

// DeletePlaceholderSettingsFromClientSession delete items from ClientSession
func DeletePlaceholderSettingsFromClientSession(session base.ClientSession) {
	data := PlaceholderSettingsFromClientSession(session)
	if data == nil {
		logrus.Warningln("Invalid type of PlaceholderSettings")
		session.DeleteData(placeholdersSettingKey)
		// do nothing because it's invalid
		return
	}
	for key := range data {
		delete(data, key)
	}
	bindPlaceholdersPool.Put(data)
	session.DeleteData(placeholdersSettingKey)
}
