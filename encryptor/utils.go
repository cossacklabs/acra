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
	"github.com/cossacklabs/acra/sqlparser"
)

var errNotFoundtable = errors.New("not found table for alias")
var errNotSupported = errors.New("not supported type of sql node")

type columnInfo struct {
	Name  string
	Table string
	Alias string
}

var errEmptyTableExprs = errors.New("empty table exprs")

// getFirstTableWithoutAlias search table name from "FROM" expression which has not any alias
// if more than one table specified without alias then return errNotFoundTable
func getFirstTableWithoutAlias(fromExpr sqlparser.TableExprs) (string, error) {
	if len(fromExpr) == 0 {
		return "", errEmptyTableExprs
	}
	var name string
	for _, tblExpr := range fromExpr {
		aliased, ok := tblExpr.(*sqlparser.AliasedTableExpr)
		if !ok {
			continue
		}
		if !aliased.As.IsEmpty() {
			continue
		}
		tableName, ok := aliased.Expr.(sqlparser.TableName)
		if !ok {
			continue
		}
		if name != "" {
			return "", errors.New("more than 1 table without alias")
		}
		name = tableName.Name.RawValue()
	}
	if name == "" {
		return "", errNotFoundtable
	}
	return name, nil
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
		if alias == val.Name.RawValue() {
			return columnInfo{Name: columnName, Table: alias}, nil
		}
		return columnInfo{}, errNotFoundtable
	case *sqlparser.AliasedTableExpr:
		if val.As.IsEmpty() {
			return findTableName(alias, columnName, val.Expr)
		}
		if val.As.RawValue() == alias {
			if tblName, ok := val.Expr.(sqlparser.TableName); ok {
				return findTableName(tblName.Name.RawValue(), columnName, val.Expr)
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
				} else if aliasExpr.As.EqualString(alias) {
					// select t1.col1 as columnName
					switch aliasVal := aliasExpr.Expr.(type) {
					case *sqlparser.ColName:
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
	}
	return columnInfo{}, errNotFoundtable
}

func mapColumnsToAliases(selectQuery *sqlparser.Select) []*columnInfo {
	searchTables := make(map[string]bool, len(selectQuery.SelectExprs))
	for _, expr := range selectQuery.SelectExprs {
		if alias, ok := expr.(*sqlparser.AliasedExpr); ok {
			if colName, ok := alias.Expr.(*sqlparser.ColName); ok {
				searchTables[colName.Qualifier.Name.RawValue()] = true
			}
		}
	}
	out := make([]*columnInfo, 0, len(selectQuery.SelectExprs))
	for _, expr := range selectQuery.SelectExprs {
		aliased, ok := expr.(*sqlparser.AliasedExpr)
		if ok {
			colName, ok := aliased.Expr.(*sqlparser.ColName)
			if ok {
				if colName.Qualifier.Name.IsEmpty() {
					firstTable, err := getFirstTableWithoutAlias(selectQuery.From)
					if err != nil {
						out = append(out, nil)
						continue
					}
					info, err := findTableName(firstTable, colName.Name.String(), selectQuery.From)
					if err == nil {
						info.Alias = firstTable
						out = append(out, &info)
						continue
					}
				} else {
					info, err := findTableName(colName.Qualifier.Name.RawValue(), colName.Name.String(), selectQuery.From)
					if err == nil {
						info.Alias = colName.Qualifier.Name.RawValue()
						out = append(out, &info)
						continue
					}
				}
			}
		}
		out = append(out, nil)
	}
	return out
}
