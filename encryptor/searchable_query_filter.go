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
	exprs := filter.filterComparisonExprs(statement)
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
	// And even then, we can work only with tables that we have an encryption schema for.
	var encryptableTables []*AliasedTableName
	for _, table := range tables {
		if v := filter.schemaStore.GetTableSchema(table.TableName.Name.ValueForConfig()); v != nil {
			encryptableTables = append(encryptableTables, table)
		}
	}
	if len(encryptableTables) == 0 {
		return nil, nil
	}
	return tables[0], NewAliasToTableMapFromTables(encryptableTables)
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

func (filter *SearchableQueryFilter) filterComparisonExprs(statement sqlparser.Statement) []*sqlparser.ComparisonExpr {
	// Walk through WHERE clauses of a SELECT statements...
	whereExprs, err := getWhereStatements(statement)
	if err != nil {
		logrus.WithError(err).Debugln("Failed to extract WHERE clauses")
		return nil
	}
	// ...and find all eligible comparison expressions in them.
	var exprs []*sqlparser.ComparisonExpr
	for _, whereExpr := range whereExprs {
		comparisonExprs, err := getEqualComparisonExprs(whereExpr)
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

func (filter *SearchableQueryFilter) getTableSchemaOfColumn(column *sqlparser.ColName, defaultTable *AliasedTableName, aliasedTables AliasToTableMap) config.TableSchema {
	if column.Qualifier.Qualifier.IsEmpty() {
		return filter.schemaStore.GetTableSchema(defaultTable.TableName.Name.ValueForConfig())
	}
	tableName := aliasedTables[column.Qualifier.Name.ValueForConfig()]
	return filter.schemaStore.GetTableSchema(tableName)
}

func getWhereStatements(stmt sqlparser.Statement) ([]*sqlparser.Where, error) {
	var whereStatements []*sqlparser.Where
	err := sqlparser.Walk(func(node sqlparser.SQLNode) (kontinue bool, err error) {
		where, ok := node.(*sqlparser.Where)
		if ok {
			whereStatements = append(whereStatements, where)
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

// getEqualComparisonExprs return only <ColName> = <VALUE> or <ColName> != <VALUE> or <ColName> <=> <VALUE> expressions
func getEqualComparisonExprs(stmt sqlparser.SQLNode) ([]*sqlparser.ComparisonExpr, error) {
	var exprs []*sqlparser.ComparisonExpr
	err := sqlparser.Walk(func(node sqlparser.SQLNode) (kontinue bool, err error) {
		if comparisonExpr, ok := node.(*sqlparser.ComparisonExpr); ok {
			if sqlVal, ok := comparisonExpr.Right.(*sqlparser.SQLVal); ok && isSupportedSQLVal(sqlVal) {
				if comparisonExpr.Operator == sqlparser.EqualStr || comparisonExpr.Operator == sqlparser.NotEqualStr || comparisonExpr.Operator == sqlparser.NullSafeEqualStr {
					if _, ok := comparisonExpr.Left.(*sqlparser.ColName); ok {
						exprs = append(exprs, comparisonExpr)
					}
				}
			}
		}
		return true, nil
	}, stmt)
	return exprs, err
}
