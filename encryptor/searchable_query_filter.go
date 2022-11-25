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
	"errors"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/sirupsen/logrus"
)

// ErrUnsupportedQueryType represent error related unsupported Query type
var ErrUnsupportedQueryType = errors.New("unsupported Query type")

// SearchableQueryFilterMode represent the mode work of SearchableQueryFilter
type SearchableQueryFilterMode int

// QueryFilterModeSearchableEncryption list of supported modes for filtering comparisons for searchable and tokenized values
const (
	QueryFilterModeSearchableEncryption = iota
	QueryFilterModeConsistentTokenization
)

// SearchableExprItem represent the filtered value found by SearchableQueryFilter
type SearchableExprItem struct {
	Expr    *sqlparser.ComparisonExpr
	Setting config.ColumnEncryptionSetting
}

// SearchableQueryFilter filter searchable expression based on SearchableQueryFilterMode
type SearchableQueryFilter struct {
	mode        SearchableQueryFilterMode
	schemaStore config.TableSchemaStore
}

// NewSearchableQueryFilter create new SearchableQueryFilter from schemaStore and SearchableQueryFilterMode
func NewSearchableQueryFilter(schemaStore config.TableSchemaStore, mode SearchableQueryFilterMode) *SearchableQueryFilter {
	return &SearchableQueryFilter{
		schemaStore: schemaStore,
		mode:        mode,
	}
}

// FilterSearchableComparisons filter search comparisons from statement
func (filter *SearchableQueryFilter) FilterSearchableComparisons(statement sqlparser.Statement) []SearchableExprItem {
	tableExps, err := filter.filterTableExpressions(statement)
	if err != nil {
		logrus.Debugln("Unsupported search query")
		return nil
	}

	defaultTable, aliasedTables := filter.filterInterestingTables(tableExps)
	if len(aliasedTables) == 0 {
		logrus.Debugln("No encryptable tables in search query")
		return nil
	}

	// Now take a closer look at WHERE clauses of the statement. We need only expressions
	// which are simple equality comparisons, like "WHERE column = value".
	exprs := filter.filterComparisonExprs(statement, defaultTable, aliasedTables)
	if len(exprs) == 0 {
		logrus.Debugln("No eligible comparisons in search query")
		return nil
	}
	// And among those expressions, not all may refer to columns with searchable encryption
	// enabled for them. Leave only those expressions which are searchable.
	searchableExprs := filter.filterComparisons(exprs, defaultTable, aliasedTables)
	if len(exprs) == 0 {
		logrus.Debugln("No searchable comparisons in search query")
		return nil
	}
	return searchableExprs
}

func (filter *SearchableQueryFilter) filterInterestingTables(fromExp sqlparser.TableExprs) (*AliasedTableName, AliasToTableMap) {
	// Not all SELECT statements refer to tables at all.
	tables := GetTablesWithAliases(fromExp)
	if len(tables) == 0 {
		return nil, nil
	}

	var defaultTable *AliasedTableName
	var defaultTableName string
	// if query contains table without alias we need to detect default table
	// if no, we can ignore default table and AliasToTableMap will be used to map ColName with encryptor_config
	if hasTablesWithoutAliases(fromExp) {
		var err error
		defaultTableName, err = getFirstTableWithoutAlias(fromExp)
		if err != nil {
			logrus.WithError(err).Debugln("Failed to find first table without alias")
			return nil, nil
		}
	}

	// And even then, we can work only with tables that we have an encryption schema for.
	var encryptableTables []*AliasedTableName

	for _, table := range tables {
		if defaultTableName == table.TableName.Name.ValueForConfig() {
			defaultTable = table
		}

		if v := filter.schemaStore.GetTableSchema(table.TableName.Name.ValueForConfig()); v != nil {
			encryptableTables = append(encryptableTables, table)
		}
	}
	if len(encryptableTables) == 0 {
		return nil, nil
	}
	return defaultTable, NewAliasToTableMapFromTables(encryptableTables)
}

func (filter *SearchableQueryFilter) filterTableExpressions(statement sqlparser.Statement) (sqlparser.TableExprs, error) {
	switch query := statement.(type) {
	case *sqlparser.Select:
		return query.From, nil
	case *sqlparser.Update:
		return query.TableExprs, nil
	case *sqlparser.Delete:
		return query.TableExprs, nil
	case *sqlparser.Insert:
		// only support INSERT INTO table2 SELECT * FROM test_table WHERE data1='somedata' syntax for INSERTs
		if selectInInsert, ok := query.Rows.(*sqlparser.Select); ok {
			return selectInInsert.From, nil
		}
		return nil, ErrUnsupportedQueryType
	default:
		return nil, ErrUnsupportedQueryType
	}
}

func (filter *SearchableQueryFilter) filterComparisonExprs(statement sqlparser.Statement, defaultTable *AliasedTableName, aliasedTables AliasToTableMap) []*sqlparser.ComparisonExpr {
	// Walk through WHERE clauses of a SELECT statements...
	whereExprs, err := getWhereStatements(statement)
	if err != nil {
		logrus.WithError(err).Debugln("Failed to extract WHERE clauses")
		return nil
	}
	// ...and find all eligible comparison expressions in them.
	var exprs []*sqlparser.ComparisonExpr
	for _, whereExpr := range whereExprs {
		comparisonExprs, err := filter.getColumnEqualComparisonExprs(whereExpr, defaultTable, aliasedTables)
		if err != nil {
			logrus.WithError(err).Debugln("Failed to extract comparison expressions")
			return nil
		}
		exprs = append(exprs, comparisonExprs...)
	}
	return exprs
}

func (filter *SearchableQueryFilter) filterComparisons(exprs []*sqlparser.ComparisonExpr, defaultTable *AliasedTableName, aliasedTables AliasToTableMap) []SearchableExprItem {
	filtered := make([]SearchableExprItem, 0, len(exprs))
	for _, expr := range exprs {
		// Leave out comparisons of columns which do not have a schema after alias resolution.
		column := expr.Left.(*sqlparser.ColName)
		schema := filter.getTableSchemaOfColumn(column, defaultTable, aliasedTables)
		if schema == nil {
			continue
		}
		// Also leave out those columns which are not searchable.
		columnName := column.Name.String()
		encryptionSetting := schema.GetColumnEncryptionSettings(columnName)

		if encryptionSetting == nil {
			continue
		}

		isComparableSetting := encryptionSetting.IsSearchable()
		if filter.mode == QueryFilterModeConsistentTokenization {
			isComparableSetting = encryptionSetting.IsConsistentTokenization()
		}

		if isComparableSetting {
			filtered = append(filtered, SearchableExprItem{Expr: expr, Setting: encryptionSetting})
		}
	}
	return filtered
}

func (filter *SearchableQueryFilter) getColumnSetting(column *sqlparser.ColName, defaultTable *AliasedTableName, aliasedTables AliasToTableMap) config.ColumnEncryptionSetting {
	schema := filter.getTableSchemaOfColumn(column, defaultTable, aliasedTables)
	if schema == nil {
		return nil
	}
	// Also leave out those columns which are not searchable.
	columnName := column.Name.ValueForConfig()
	return schema.GetColumnEncryptionSettings(columnName)
}

func (filter *SearchableQueryFilter) getTableSchemaOfColumn(column *sqlparser.ColName, defaultTable *AliasedTableName, aliasedTables AliasToTableMap) config.TableSchema {
	if column.Qualifier.Qualifier.IsEmpty() && column.Qualifier.Name.IsEmpty() {
		return filter.schemaStore.GetTableSchema(defaultTable.TableName.Name.ValueForConfig())
	}
	tableName := aliasedTables[column.Qualifier.Name.ValueForConfig()]
	return filter.schemaStore.GetTableSchema(tableName)
}

func getWhereStatements(stmt sqlparser.Statement) ([]*sqlparser.Where, error) {
	var whereStatements []*sqlparser.Where
	err := sqlparser.Walk(func(node sqlparser.SQLNode) (kontinue bool, err error) {
		switch nodeType := node.(type) {
		case *sqlparser.Where:
			whereStatements = append(whereStatements, nodeType)
		case sqlparser.JoinCondition:
			whereStatements = append(whereStatements, &sqlparser.Where{
				Type: "on",
				Expr: nodeType.On,
			})
		}
		return true, nil
	}, stmt)
	return whereStatements, err
}

func isSupportedSQLVal(val *sqlparser.SQLVal) bool {
	switch val.Type {
	case sqlparser.PgEscapeString, sqlparser.HexVal, sqlparser.StrVal, sqlparser.PgPlaceholder, sqlparser.ValArg, sqlparser.IntVal:
		return true
	}
	return false
}

// getColumnEqualComparisonExprs return only <ColName> = <VALUE> or <ColName> != <VALUE> or <ColName> <=> <VALUE> expressions
func (filter *SearchableQueryFilter) getColumnEqualComparisonExprs(stmt sqlparser.SQLNode, defaultTable *AliasedTableName, aliasedTables AliasToTableMap) ([]*sqlparser.ComparisonExpr, error) {
	var exprs []*sqlparser.ComparisonExpr
	err := sqlparser.Walk(func(node sqlparser.SQLNode) (kontinue bool, err error) {
		if comparisonExpr, ok := node.(*sqlparser.ComparisonExpr); ok {
			lColumn, ok := comparisonExpr.Left.(*sqlparser.ColName)
			if !ok {
				return true, nil
			}

			lColumnSetting := filter.getColumnSetting(lColumn, defaultTable, aliasedTables)
			if lColumnSetting == nil {
				return true, nil
			}

			// check if left column isSearchable or consistent tokenized and right column is sqlparser.ColName
			// we want to log the warn message that searchable tokenization/encryption can work only with <ColName> = <VALUE> statements
			// however, there is one exception - for searchable encryption it can be the scenario where we have:  join table1 t1 on t1.surname = t2.surname
			// and if t1 and t2 are tables from encryptor_config and t1.surname and t2.surname are searchable, we want to have: join table1 t1 on substr(t1.surname, ...) = substr(t2.surname, ...)
			if lColumnSetting.IsSearchable() || lColumnSetting.IsConsistentTokenization() {
				if rColumn, ok := comparisonExpr.Right.(*sqlparser.ColName); ok {
					// get right columnSetting to check weather it is searchable too
					rColumnSetting := filter.getColumnSetting(rColumn, defaultTable, aliasedTables)
					if rColumnSetting != nil {
						if rColumnSetting.IsSearchable() {
							exprs = append(exprs, comparisonExpr)
							return true, nil
						}
					}

					logrus.Infoln("Searchable encryption/tokenization support equal comparison only by SQLVal but not by ColName")
				}
			}

			if sqlVal, ok := comparisonExpr.Right.(*sqlparser.SQLVal); ok && isSupportedSQLVal(sqlVal) {
				if comparisonExpr.Operator == sqlparser.EqualStr || comparisonExpr.Operator == sqlparser.NotEqualStr ||
					comparisonExpr.Operator == sqlparser.NullSafeEqualStr || comparisonExpr.Operator == sqlparser.LikeStr ||
					comparisonExpr.Operator == sqlparser.NotLikeStr {
					if _, ok := comparisonExpr.Left.(*sqlparser.ColName); ok {
						switch comparisonExpr.Operator {
						case sqlparser.EqualStr, sqlparser.NullSafeEqualStr, sqlparser.LikeStr:
							comparisonExpr.Operator = sqlparser.EqualStr
							break
						case sqlparser.NotEqualStr, sqlparser.NotLikeStr:
							comparisonExpr.Operator = sqlparser.NotEqualStr
							break
						}

						exprs = append(exprs, comparisonExpr)
					}
				}
			}
		}
		return true, nil
	}, stmt)
	return exprs, err
}
