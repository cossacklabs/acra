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
	"errors"
	"strings"

	pg_query "github.com/Zhaars/pg_query_go/v4"
	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/encryptor/base/config"
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

const SubstrFuncName = "substr"

// SearchableExprItem represent the filtered value found by SearchableQueryFilter
type SearchableExprItem struct {
	Expr    *pg_query.A_Expr
	Setting config.ColumnEncryptionSetting
}

// SearchableQueryFilter filter searchable expression based on SearchableQueryFilterMode
type SearchableQueryFilter struct {
	schemaStore config.TableSchemaStore
}

// NewSearchableQueryFilter create new SearchableQueryFilter from schemaStore and SearchableQueryFilterMode
func NewSearchableQueryFilter(schemaStore config.TableSchemaStore) *SearchableQueryFilter {
	return &SearchableQueryFilter{
		schemaStore: schemaStore,
	}
}

// FilterSearchableComparisons filter search comparisons from statement
func (filter *SearchableQueryFilter) FilterSearchableComparisons(result *pg_query.ParseResult) []SearchableExprItem {
	tableExps, err := filterTableExpressions(result)
	if err != nil {
		logrus.Debugln("Unsupported search query")
		return nil
	}

	// Walk through WHERE clauses of a SELECT statements...
	whereExprs, err := GetWhereStatements(result)
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
func (filter *SearchableQueryFilter) ChangeSearchableOperator(expr *pg_query.A_Expr) {
	switch expr.Name[0].GetString_().GetSval() {
	//case sqlparser.EqualStr, sqlparser.NullSafeEqualStr, sqlparser.LikeStr, sqlparser.ILikeStr:
	//	expr.Operator = sqlparser.EqualStr
	//case sqlparser.NotEqualStr, sqlparser.NotLikeStr, sqlparser.NotILikeStr:
	//	expr.Operator = sqlparser.NotEqualStr
	}
}

func filterTableExpressions(parseResult *pg_query.ParseResult) ([]*pg_query.Node, error) {
	switch {
	case parseResult.Stmts[0].Stmt.GetSelectStmt() != nil:
		stmt := parseResult.Stmts[0].Stmt.GetSelectStmt()
		return stmt.FromClause, nil
	case parseResult.Stmts[0].Stmt.GetInsertStmt() != nil:
		// only support INSERT INTO table2 SELECT * FROM test_table WHERE data1='somedata' syntax for INSERTs
		if selectStmt := parseResult.Stmts[0].Stmt.GetInsertStmt().GetSelectStmt(); selectStmt != nil {
			return selectStmt.GetSelectStmt().FromClause, nil
		}
		return nil, ErrUnsupportedQueryType
	case parseResult.Stmts[0].Stmt.GetUpdateStmt() != nil:
		stmt := parseResult.Stmts[0].Stmt.GetUpdateStmt()
		return []*pg_query.Node{{
			Node: &pg_query.Node_RangeVar{
				RangeVar: stmt.GetRelation(),
			},
		}}, nil
	case parseResult.Stmts[0].Stmt.GetDeleteStmt() != nil:
		stmt := parseResult.Stmts[0].Stmt.GetDeleteStmt()
		return []*pg_query.Node{{
			Node: &pg_query.Node_RangeVar{
				RangeVar: stmt.GetRelation(),
			},
		}}, nil
	default:
		return nil, ErrUnsupportedQueryType
	}
}

// filterColumnEqualComparisonExprs return only <ColName> = <VALUE> or <ColName> != <VALUE> or <ColName> <=> <VALUE> expressions
func (filter *SearchableQueryFilter) filterColumnEqualComparisonExprs(whereNode *pg_query.Node, tableExpr []*pg_query.Node) ([]SearchableExprItem, error) {
	var exprs []SearchableExprItem

	err := pg_query.Walk(func(node *pg_query.Node) (kontinue bool, err error) {
		expr := node.GetAExpr()
		if expr == nil {
			return true, nil
		}

		var lColumn = expr.Lexpr.GetColumnRef()
		if expr.Lexpr.GetColumnRef() == nil {
			//handle case if query was processed by searchable encryptor
			if funcCall := expr.Lexpr.GetFuncCall(); funcCall != nil {
				funcName := funcCall.GetFuncname()
				if len(funcName) == 1 && strings.HasPrefix(funcName[0].GetString_().GetSval(), SubstrFuncName) {
					lColumn = funcCall.GetArgs()[0].GetColumnRef()
				} else {
					return true, nil
				}
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
		if rColumn := expr.Rexpr.GetColumnRef(); rColumn != nil {
			// get right columnSetting to check weather it is searchable too
			columnInfo, err := FindColumnInfo(tableExpr, rColumn, filter.schemaStore)
			if err != nil {
				return true, nil
			}

			rColumnSetting := GetColumnSetting(rColumn, columnInfo.Table, filter.schemaStore)
			if rColumnSetting != nil {
				if rColumnSetting.IsSearchable() {
					exprs = append(exprs, SearchableExprItem{
						Expr:    expr,
						Setting: rColumnSetting,
					})
					return true, nil
				}
			}

			logrus.Infoln("Searchable encryption/tokenization support equal comparison only by SQLVal but not by ColName")
		}

		if expr.Rexpr.GetAConst() != nil || expr.Rexpr.GetParamRef() != nil {
			if len(expr.Name) == 1 {
				if val := expr.Name[0].GetString_(); val != nil && (val.GetSval() == "=" || val.GetSval() == "<>") {
					exprs = append(exprs, SearchableExprItem{
						Expr:    expr,
						Setting: lColumnSetting,
					})
				}
			}
		}

		return true, nil
	}, whereNode)
	return exprs, err
}
