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

package decryptor

import "github.com/cossacklabs/acra/sqlparser"

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
	case sqlparser.PgEscapeString, sqlparser.HexVal, sqlparser.StrVal, sqlparser.PgPlaceholder, sqlparser.ValArg:
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
