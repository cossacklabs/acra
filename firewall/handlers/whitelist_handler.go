package handlers

import (
	"errors"
	"github.com/xwb1989/sqlparser"
	"reflect"
	"strings"
)

type WhitelistHandler struct {
	queries []string
	tables  []string
	rules   []string
}

func (handler *WhitelistHandler) CheckQuery(query string) error {

	//Check queries
	if len(handler.queries) != 0 {
		yes, _ := contains(handler.queries, query)
		if !yes {
			return ErrQueryNotInWhitelist
		}
	}

	//Check tables
	if len(handler.tables) != 0 {
		parsedQuery, err := sqlparser.Parse(query)
		if err != nil {
			return ErrParseTablesWhitelist
		}

		switch parsedQuery := parsedQuery.(type) {
		case *sqlparser.Select:
			allowedTablesCounter := 0
			for _, allowedTable := range handler.tables {
				for _, table := range parsedQuery.From {
					if strings.EqualFold(sqlparser.String(table.(*sqlparser.AliasedTableExpr).Expr), allowedTable) {
						allowedTablesCounter++
					}
				}
			}
			if allowedTablesCounter != len(parsedQuery.From) {
				return ErrAccessToForbiddenTableWhitelist
			}

		case *sqlparser.Insert:

			tableIsAllowed := false
			for _, allowedTable := range handler.tables {
				if strings.EqualFold(parsedQuery.Table.Name.String(), allowedTable) {
					tableIsAllowed = true
				}
			}
			if !tableIsAllowed {
				return ErrAccessToForbiddenTableWhitelist
			}
		case *sqlparser.Update:
		}
	}

	//Check rules
	if len(handler.rules) != 0 {
		violationOccured, err := handler.testRulesViolation(query)
		if err != nil {
			return ErrParseSqlRuleWhitelist
		}
		if violationOccured {
			return ErrForbiddenSqlStructureWhitelist
		}
	}
	return nil
}

func (handler *WhitelistHandler) Reset() {

	handler.queries = nil
	handler.tables = nil
	handler.rules = nil
}

func (handler *WhitelistHandler) AddQueries(queries []string) error {

	for _, query := range queries {
		handler.queries = append(handler.queries, query)
		_, err := sqlparser.Parse(query)
		if err != nil {
			return ErrQuerySyntaxError
		}
	}
	handler.queries = removeDuplicates(handler.queries)

	return nil
}

func (handler *WhitelistHandler) RemoveQueries(queries []string) {

	for _, query := range handler.queries {
		yes, index := contains(handler.queries, query)
		if yes {
			handler.queries = append(handler.queries[:index], handler.queries[index+1:]...)
		}
	}
}

func (handler *WhitelistHandler) AddTables(tableNames []string) {
	for _, tableName := range tableNames {
		handler.tables = append(handler.tables, tableName)
	}

	handler.tables = removeDuplicates(handler.tables)
}

func (handler *WhitelistHandler) RemoveTables(tableNames []string) {
	for _, query := range tableNames {
		yes, index := contains(handler.tables, query)
		if yes {
			handler.tables = append(handler.tables[:index], handler.tables[index+1:]...)
		}
	}
}

func (handler *WhitelistHandler) AddRules(rules []string) error {
	for _, rule := range rules {
		handler.rules = append(handler.rules, rule)
		_, err := sqlparser.Parse(rule)
		if err != nil {
			return ErrStructureSyntaxError
		}
	}

	handler.rules = removeDuplicates(handler.rules)

	return nil
}

func (handler *WhitelistHandler) RemoveRules(rules []string) {
	for _, rule := range rules {
		yes, index := contains(handler.rules, rule)
		if yes {
			handler.rules = append(handler.rules[:index], handler.rules[index+1:]...)
		}
	}
}

func (handler *WhitelistHandler) testRulesViolation(query string) (bool, error) {

	if sqlparser.Preview(query) != sqlparser.StmtSelect {
		return true, errors.New("non-select queries are not supported")
	}

	//parse one rule and get forbidden tables and columns for specific 'where' clause
	var whereClause sqlparser.SQLNode
	var tables sqlparser.TableExprs
	var columns sqlparser.SelectExprs

	//Parse each rule and then test query
	for _, rule := range handler.rules {
		parsedRule, err := sqlparser.Parse(rule)
		if err != nil {
			return true, err
		}

		switch parsedRule := parsedRule.(type) {

		case *sqlparser.Select:
			whereClause = parsedRule.Where.Expr
			tables = parsedRule.From
			columns = parsedRule.SelectExprs

			dangerousSelect, err := handler.isDangerousSelect(query, whereClause, tables, columns)
			if err != nil {
				return true, err
			}

			if dangerousSelect {
				return true, nil
			}

		case *sqlparser.Insert:
			return true, ErrNotImplemented
		default:
			return true, ErrNotImplemented
		}

		_ = whereClause
		_ = tables
		_ = columns
	}

	return false, nil
}

func (handler *WhitelistHandler) isDangerousSelect(selectQuery string, allowedWhere sqlparser.SQLNode, allowedTables sqlparser.TableExprs, allowedColumns sqlparser.SelectExprs) (bool, error) {

	parsedSelectQuery, err := sqlparser.Parse(selectQuery)
	if err != nil {
		return true, err
	}

	evaluatedStmt := parsedSelectQuery.(*sqlparser.Select)

	if strings.EqualFold(sqlparser.String(allowedWhere), sqlparser.String(evaluatedStmt.Where.Expr)) {
		if handler.isAllowedTableAccess(evaluatedStmt.From, allowedTables) {
			if handler.isAllowedColumnAccess(evaluatedStmt.SelectExprs, allowedColumns) {
				return false, nil
			}
		}
	}
	return true, nil
}

func (handler *WhitelistHandler) isAllowedTableAccess(tablesToEvaluate sqlparser.TableExprs, allowedTables sqlparser.TableExprs) bool {

	accessOnlyToAllowedTables := true

	for _, tableToEvaluate := range tablesToEvaluate {
		for _, allowedTable := range allowedTables {
			if !reflect.DeepEqual(tableToEvaluate.(*sqlparser.AliasedTableExpr).Expr, allowedTable.(*sqlparser.AliasedTableExpr).Expr) {
				accessOnlyToAllowedTables = false
			}
		}
	}

	return accessOnlyToAllowedTables
}

func (handler *WhitelistHandler) isAllowedColumnAccess(columnsToEvaluate sqlparser.SelectExprs, allowedColumns sqlparser.SelectExprs) bool {

	if strings.EqualFold(sqlparser.String(allowedColumns), "*") {
		return true
	}

	accessOnlyToAllowedColumns := true

	for _, columnToEvaluate := range columnsToEvaluate {
		for _, allowedColumn := range allowedColumns {
			if !reflect.DeepEqual(columnToEvaluate, allowedColumn) {
				accessOnlyToAllowedColumns = false
			}
		}
	}
	return accessOnlyToAllowedColumns
}
