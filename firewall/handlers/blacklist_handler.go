package handlers

import (
	"errors"
	"strings"
	"reflect"
	"github.com/xwb1989/sqlparser"
)

type BlacklistHandler struct {
	queries [] string
	tables  [] string
	rules   [] string
}

func(handler * BlacklistHandler) CheckQuery(query string) error {

	//Check queries
	if len(handler.queries) != 0 {
		//Check that query is not in blacklist
		yes, _ := contains(handler.queries, query)
		if yes {
			return ErrQueryInBlacklist
		}
	}

	//Check tables
	if len(handler.tables) != 0 {
		parsedQuery, err := sqlparser.Parse(query)
		if err != nil {
			return ErrParseTablesBlacklist
		}

		switch parsedQuery := parsedQuery.(type) {
		case *sqlparser.Select:
			for _, forbiddenTable := range handler.tables {
				for _, table := range parsedQuery.From{
					if strings.EqualFold(sqlparser.String(table.(*sqlparser.AliasedTableExpr).Expr), forbiddenTable) {
						return ErrAccessToForbiddenTableBlacklist
					}
				}
			}

		case *sqlparser.Insert:
			for _, forbiddenTable := range handler.tables {
				if strings.EqualFold(parsedQuery.Table.Name.String(), forbiddenTable) {
					return ErrAccessToForbiddenTableBlacklist
				}
			}

		case *sqlparser.Update:
			return ErrNotImplemented
		}
	}

	//Check rules
	if len(handler.rules) != 0 {
		violationOccured, err := handler.testRulesViolation(query)
		if err != nil {
			return ErrParseSqlRuleBlacklist
		}
		if violationOccured {
			return ErrForbiddenSqlStructureBlacklist
		}
	}
	return nil
}

func (handler * BlacklistHandler) Reset(){
	handler.queries = nil
	handler.tables = nil
	handler.rules = nil
}

func(handler * BlacklistHandler) AddQueries(queries []string) error {

	for _, query := range queries{
		_, err := sqlparser.Parse(query)
		if err != nil {
			return ErrQuerySyntaxError
		}
		handler.queries = append(handler.queries, query)
	}

	handler.queries = removeDuplicates(handler.queries)

	return nil
}

func(handler * BlacklistHandler) RemoveQueries(queries []string){

	for _, query := range queries{
		yes, index := contains(handler.queries, query)
		if yes {
			handler.queries = append(handler.queries[:index], handler.queries[index+1:]...)
		}
	}
}

func (handler * BlacklistHandler) AddTables(tableNames []string){

	for _, tableName := range tableNames{
		handler.tables = append(handler.tables, tableName)
	}

	handler.tables = removeDuplicates(handler.tables)
}

func (handler * BlacklistHandler) RemoveTables(tableNames []string) {

	for _, query := range tableNames{
		yes, index := contains(handler.tables, query)
		if yes {
			handler.tables = append(handler.tables[:index], handler.tables[index+1:]...)
		}
	}
}

func (handler * BlacklistHandler) AddRules(rules []string) error {
	for _, rule := range rules{
		handler.rules = append(handler.rules, rule)
		_, err := sqlparser.Parse(rule)
		if err != nil {
			return ErrStructureSyntaxError
		}
	}

	handler.rules = removeDuplicates(handler.rules)

	return nil
}

func (handler * BlacklistHandler) RemoveRules(rules []string){
	for _, rule := range rules{
		yes, index := contains(handler.rules, rule)
		if yes {
			handler.rules = append(handler.rules[:index], handler.rules[index+1:]...)
		}
	}
}





func (handler *BlacklistHandler) testRulesViolation(query string) (bool, error) {

	if sqlparser.Preview(query) != sqlparser.StmtSelect{
		return true, errors.New("non-select queries are not supported")
	}

	//parse one rule and get forbidden tables and columns for specific 'where' clause
	var whereClause sqlparser.SQLNode
	var tables sqlparser.TableExprs
	var columns sqlparser.SelectExprs

	//Parse each rule and then test query
	for _, rule := range handler.rules{
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

func (handler *BlacklistHandler) isDangerousSelect(selectQuery string, forbiddenWhere sqlparser.SQLNode, forbiddenTables sqlparser.TableExprs, forbiddenColumns sqlparser.SelectExprs) (bool, error) {

	parsedSelectQuery, err := sqlparser.Parse(selectQuery)
	if err != nil {
		return true, err
	}

	evaluatedStmt := parsedSelectQuery.(*sqlparser.Select)

	if evaluatedStmt.Where != nil {
		if strings.EqualFold(sqlparser.String(forbiddenWhere), sqlparser.String(evaluatedStmt.Where.Expr)) {
			if handler.isForbiddenTableAccess(evaluatedStmt.From, forbiddenTables) {
				if handler.isForbiddenColumnAccess(evaluatedStmt.SelectExprs, forbiddenColumns){
					return true, nil
				}
			}
		}
	} else {
		if handler.isForbiddenTableAccess(evaluatedStmt.From, forbiddenTables) {
			if handler.isForbiddenColumnAccess(evaluatedStmt.SelectExprs, forbiddenColumns){
				return true, nil
			}
		}
	}

	return false, nil
}

func (handler *BlacklistHandler) isForbiddenTableAccess(tablesToEvaluate sqlparser.TableExprs, forbiddenTables sqlparser.TableExprs) bool {
	for _, tableToEvaluate := range tablesToEvaluate {
		for _, forbiddenTable := range forbiddenTables {
			if reflect.DeepEqual(tableToEvaluate.(*sqlparser.AliasedTableExpr).Expr, forbiddenTable.(*sqlparser.AliasedTableExpr).Expr) {
				return true
			}
		}
	}
	return false
}

func (handler *BlacklistHandler) isForbiddenColumnAccess(columnsToEvaluate sqlparser.SelectExprs, forbiddenColumns sqlparser.SelectExprs) bool {
	if strings.EqualFold(sqlparser.String(forbiddenColumns), "*"){
		return true
	}

	for _, columnToEvaluate := range columnsToEvaluate {
		for _, forbiddenColumn := range forbiddenColumns{
			if reflect.DeepEqual(columnToEvaluate, forbiddenColumn) {
				return true
			}
		}
	}
	return false
}

