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

package mysql

import (
	"errors"

	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/sqlparser"
)

// ErrUnsupportedQueryType represent error related unsupported Query type
var ErrUnsupportedQueryType = errors.New("unsupported Query type")

// SearchableExprItem represent the filtered value found by SearchableQueryFilter
type SearchableExprItem struct {
	Expr    *sqlparser.ComparisonExpr
	Setting config.ColumnEncryptionSetting
}

// SearchableQueryFilter filter searchable expression based on SearchableQueryFilterMode
type SearchableQueryFilter struct {
	mode        base.SearchableQueryFilterMode
	schemaStore config.TableSchemaStore
}

// NewSearchableQueryFilter create new SearchableQueryFilter from schemaStore and SearchableQueryFilterMode
func NewSearchableQueryFilter(schemaStore config.TableSchemaStore, mode base.SearchableQueryFilterMode) *SearchableQueryFilter {
	return &SearchableQueryFilter{
		schemaStore: schemaStore,
		mode:        mode,
	}
}

// FilterSearchableComparisons filter search comparisons from statement
func (filter *SearchableQueryFilter) FilterSearchableComparisons(statement sqlparser.Statement) []SearchableExprItem {
	tableExps, err := filterTableExpressions(statement)
	if err != nil {
		logrus.Debugln("Unsupported search query")
		return nil
	}

	// Walk through WHERE clauses of a SELECT statements...
	whereExprs, err := GetWhereStatements(statement)
	if err != nil {
		logrus.WithError(err).Debugln("Failed to extract WHERE clauses")
		return nil
	}

	var searchableExprs []SearchableExprItem
	for _, whereExpr := range whereExprs {
		comparisonExprs, err := filter.filterColumnEqualComparisonExprs(whereExpr, tableExps)
		if err != nil {
			logrus.WithError(err).Debugln("Failed to extract comparison expressions")
			return nil
		}
		searchableExprs = append(searchableExprs, comparisonExprs...)
	}

	return searchableExprs
}

// ChangeSearchableOperator change the operator of ComparisonExpr to EqualStr|NotEqualStr depending on expr.Operator
func (filter *SearchableQueryFilter) ChangeSearchableOperator(expr *sqlparser.ComparisonExpr) {
	switch expr.Operator {
	case sqlparser.EqualStr, sqlparser.NullSafeEqualStr, sqlparser.LikeStr, sqlparser.ILikeStr:
		expr.Operator = sqlparser.EqualStr
	case sqlparser.NotEqualStr, sqlparser.NotLikeStr, sqlparser.NotILikeStr:
		expr.Operator = sqlparser.NotEqualStr
	}
}

func filterTableExpressions(statement sqlparser.Statement) (sqlparser.TableExprs, error) {
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

func isSupportedSQLVal(val *sqlparser.SQLVal) bool {
	switch val.Type {
	case sqlparser.PgEscapeString, sqlparser.HexVal, sqlparser.StrVal, sqlparser.PgPlaceholder, sqlparser.ValArg, sqlparser.IntVal:
		return true
	}
	return false
}

// filterColumnEqualComparisonExprs return only <ColName> = <VALUE> or <ColName> != <VALUE> or <ColName> <=> <VALUE> expressions
func (filter *SearchableQueryFilter) filterColumnEqualComparisonExprs(stmt sqlparser.SQLNode, tableExpr sqlparser.TableExprs) ([]SearchableExprItem, error) {
	var exprs []SearchableExprItem

	err := sqlparser.Walk(func(node sqlparser.SQLNode) (kontinue bool, err error) {
		comparisonExpr, ok := node.(*sqlparser.ComparisonExpr)
		if !ok {
			return true, nil
		}

		lColumn, ok := comparisonExpr.Left.(*sqlparser.ColName)
		if !ok {
			if filter.mode == base.QueryFilterModeSearchableEncryption {
				// handle case if query was processed by searchable encryptor
				substrExpr, ok := comparisonExpr.Left.(*sqlparser.SubstrExpr)
				if !ok {
					return true, nil
				}
				lColumn = substrExpr.Name
			} else {
				return true, nil
			}
		}

		columnInfo, err := FindColumnInfo(tableExpr, lColumn, filter.schemaStore)
		if err != nil {
			return true, nil
		}

		lColumnSetting := GetColumnSetting(lColumn, columnInfo.Table, filter.schemaStore)
		if lColumnSetting == nil {
			return true, nil
		}

		if !lColumnSetting.IsSearchable() && !lColumnSetting.IsConsistentTokenization() {
			return true, nil
		}

		// check if left column isSearchable or consistent tokenized and right column is sqlparser.ColName
		// we want to log the warn message that searchable tokenization/encryption can work only with <ColName> = <VALUE> statements
		// however, there is one exception - for searchable encryption it can be the scenario where we have:  join table1 t1 on t1.surname = t2.surname
		// and if t1 and t2 are tables from encryptor_config and t1.surname and t2.surname are searchable, we want to have: join table1 t1 on substr(t1.surname, ...) = substr(t2.surname, ...)
		if rColumn, ok := comparisonExpr.Right.(*sqlparser.ColName); ok {
			// get right columnSetting to check weather it is searchable too

			columnInfo, err := FindColumnInfo(tableExpr, rColumn, filter.schemaStore)
			if err != nil {
				return true, nil
			}

			rColumnSetting := GetColumnSetting(rColumn, columnInfo.Table, filter.schemaStore)
			if rColumnSetting != nil {
				if rColumnSetting.IsSearchable() {
					exprs = append(exprs, SearchableExprItem{
						Expr:    comparisonExpr,
						Setting: rColumnSetting,
					})
					return true, nil
				}
			}

			logrus.Infoln("Searchable encryption/tokenization support equal comparison only by SQLVal but not by ColName")
		}

		if sqlVal, ok := comparisonExpr.Right.(*sqlparser.SQLVal); ok && isSupportedSQLVal(sqlVal) {
			if comparisonExpr.Operator == sqlparser.EqualStr || comparisonExpr.Operator == sqlparser.NotEqualStr || comparisonExpr.Operator == sqlparser.NullSafeEqualStr {
				exprs = append(exprs, SearchableExprItem{
					Expr:    comparisonExpr,
					Setting: lColumnSetting,
				})
			}
		}

		return true, nil
	}, stmt)
	return exprs, err
}

// ParseSearchQueryPlaceholdersSettings parse encryption settings of statement with placeholders
func ParseSearchQueryPlaceholdersSettings(statement sqlparser.Statement, schemaStore config.TableSchemaStore) map[int]config.ColumnEncryptionSetting {
	tableExps, err := filterTableExpressions(statement)
	if err != nil {
		logrus.Debugln("Unsupported search query")
		return nil
	}

	// Walk through WHERE clauses of a SELECT statements...
	whereExprs, err := GetWhereStatements(statement)
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

			columnInfo, err := FindColumnInfo(tableExps, colName, schemaStore)
			if err != nil {
				return true, nil
			}

			lColumnSetting := GetColumnSetting(colName, columnInfo.Table, schemaStore)
			if lColumnSetting == nil {
				return true, nil
			}

			if !lColumnSetting.IsSearchable() && !lColumnSetting.IsConsistentTokenization() {
				return true, nil
			}

			if sqlVal, ok := comparisonExpr.Right.(*sqlparser.SQLVal); ok && isSupportedSQLVal(sqlVal) {
				if comparisonExpr.Operator == sqlparser.EqualStr || comparisonExpr.Operator == sqlparser.NotEqualStr || comparisonExpr.Operator == sqlparser.NullSafeEqualStr {

					placeholderIndex, err := ParsePlaceholderIndex(sqlVal)
					if err == base.ErrInvalidPlaceholder {
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
