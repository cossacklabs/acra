package handlers

import (
	"errors"
	"github.com/xwb1989/sqlparser"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
)

type BlacklistHandler struct {
	queries []string
	tables  []string
	rules   []string
}

func (handler *BlacklistHandler) CheckQuery(query string) (bool, error) {
	//Check queries
	if len(handler.queries) != 0 {
		//Check that query is not in blacklist
		yes, _ := contains(handler.queries, query)
		if yes {
			return false, ErrQueryInBlacklist
		}
	}
	//Check tables
	if len(handler.tables) != 0 {
		parsedQuery, err := sqlparser.Parse(query)
		if err != nil {
			log.WithError(err).Errorln("Can't parse query in blacklist handler for check")
			return false, ErrQuerySyntaxError
		}
		switch parsedQuery := parsedQuery.(type) {
		case *sqlparser.Select:
			for _, forbiddenTable := range handler.tables {
				for _, fromStatement := range parsedQuery.From {
					switch fromStatement.(type) {
					case *sqlparser.AliasedTableExpr:
						err = handler.handleAliasedTables(fromStatement.(*sqlparser.AliasedTableExpr), forbiddenTable)
						if err != nil {
							log.WithError(err).Debugln("error from BlacklistHandler.handleAliasedTables")
							return false, ErrAccessToForbiddenTableBlacklist
						}
						break
					case *sqlparser.JoinTableExpr:
						err = handler.handleJoinedTables(fromStatement.(*sqlparser.JoinTableExpr), forbiddenTable)
						if err != nil {
							log.WithError(err).Debugln("error from BlacklistHandler.handleJoinedTables")
							return false, ErrAccessToForbiddenTableBlacklist
						}
						break
					case *sqlparser.ParenTableExpr:
						err = handler.handleParenTables(fromStatement.(*sqlparser.ParenTableExpr), forbiddenTable)
						if err != nil {
							log.WithError(err).Debugln("error from BlacklistHandler.handleParenTables")
							return false, ErrAccessToForbiddenTableBlacklist
						}
						break
					default:
						return false, ErrUnexpectedTypeError
					}
				}
			}
		case *sqlparser.Insert:
			for _, forbiddenTable := range handler.tables {
				if strings.EqualFold(parsedQuery.Table.Name.String(), forbiddenTable) {
					return false, ErrAccessToForbiddenTableBlacklist
				}
			}
		case *sqlparser.Update:
			return false, ErrNotImplemented

		default:
			return false, ErrNotImplemented
		}
	}
	//Check rules
	if len(handler.rules) != 0 {
		violationOccured, err := handler.testRulesViolation(query)
		if err != nil {
			return false, ErrParseSqlRuleBlacklist
		}
		if violationOccured {
			return false, ErrForbiddenSqlStructureBlacklist
		}
	}
	return true, nil
}

func (handler *BlacklistHandler) handleAliasedTables(statement *sqlparser.AliasedTableExpr, forbiddenTable string) error {
	if strings.EqualFold(sqlparser.String(statement.Expr), forbiddenTable) {
		return ErrAccessToForbiddenTableBlacklist
	} else {
		return nil
	}
}

func (handler *BlacklistHandler) handleJoinedTables(statement *sqlparser.JoinTableExpr, forbiddenTable string) error {
	var err error
	switch statement.LeftExpr.(type) {
	case *sqlparser.AliasedTableExpr:
		err = handler.handleAliasedTables(statement.LeftExpr.(*sqlparser.AliasedTableExpr), forbiddenTable)
	case *sqlparser.JoinTableExpr:
		err = handler.handleJoinedTables(statement.LeftExpr.(*sqlparser.JoinTableExpr), forbiddenTable)
	case *sqlparser.ParenTableExpr:
		err = handler.handleParenTables(statement.LeftExpr.(*sqlparser.ParenTableExpr), forbiddenTable)
	default:
		return ErrUnexpectedTypeError
	}
	if err != nil {
		return err
	}
	switch statement.RightExpr.(type) {
	case *sqlparser.AliasedTableExpr:
		err = handler.handleAliasedTables(statement.RightExpr.(*sqlparser.AliasedTableExpr), forbiddenTable)
	case *sqlparser.JoinTableExpr:
		err = handler.handleJoinedTables(statement.RightExpr.(*sqlparser.JoinTableExpr), forbiddenTable)
	case *sqlparser.ParenTableExpr:
		err = handler.handleParenTables(statement.RightExpr.(*sqlparser.ParenTableExpr), forbiddenTable)
	default:
		err = ErrUnexpectedTypeError
	}
	if err != nil {
		return err
	}
	return nil
}

func (handler *BlacklistHandler) handleParenTables(statement *sqlparser.ParenTableExpr, forbiddenTable string) error {
	var err error
	for _, singleExpression := range statement.Exprs {
		switch singleExpression.(type) {
		case *sqlparser.AliasedTableExpr:
			err = handler.handleAliasedTables(singleExpression.(*sqlparser.AliasedTableExpr), forbiddenTable)
		case *sqlparser.JoinTableExpr:
			err = handler.handleJoinedTables(singleExpression.(*sqlparser.JoinTableExpr), forbiddenTable)
		case *sqlparser.ParenTableExpr:
			err = handler.handleParenTables(singleExpression.(*sqlparser.ParenTableExpr), forbiddenTable)
		default:
			return ErrUnexpectedTypeError
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (handler *BlacklistHandler) Reset() {
	handler.queries = nil
	handler.tables = nil
	handler.rules = nil
}

func (handler *BlacklistHandler) Release() {
	handler.Reset()
}

func (handler *BlacklistHandler) AddQueries(queries []string) error {
	for _, query := range queries {
		handler.queries = append(handler.queries, query)
	}
	handler.queries = removeDuplicates(handler.queries)
	return nil
}

func (handler *BlacklistHandler) RemoveQueries(queries []string) {
	for _, query := range queries {
		yes, index := contains(handler.queries, query)
		if yes {
			handler.queries = append(handler.queries[:index], handler.queries[index+1:]...)
		}
	}
}

func (handler *BlacklistHandler) AddTables(tableNames []string) {
	for _, tableName := range tableNames {
		handler.tables = append(handler.tables, tableName)
	}

	handler.tables = removeDuplicates(handler.tables)
}

func (handler *BlacklistHandler) RemoveTables(tableNames []string) {
	for _, query := range tableNames {
		yes, index := contains(handler.tables, query)
		if yes {
			handler.tables = append(handler.tables[:index], handler.tables[index+1:]...)
		}
	}
}

func (handler *BlacklistHandler) AddRules(rules []string) error {
	for _, rule := range rules {
		handler.rules = append(handler.rules, rule)
		_, err := sqlparser.Parse(rule)
		if err != nil {
			log.WithError(err).Errorln("Can't parse query to add rule to blacklist handler")
			return ErrQuerySyntaxError
		}
	}
	handler.rules = removeDuplicates(handler.rules)
	return nil
}

func (handler *BlacklistHandler) RemoveRules(rules []string) {
	for _, rule := range rules {
		yes, index := contains(handler.rules, rule)
		if yes {
			handler.rules = append(handler.rules[:index], handler.rules[index+1:]...)
		}
	}
}

func (handler *BlacklistHandler) testRulesViolation(query string) (bool, error) {
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
			log.WithError(err).Errorln("Can't parse rule in blacklist handler for test")
			return true, ErrQuerySyntaxError
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
		log.WithError(err).Errorln("Can't parse query in blacklist handler to check is it dangerous select")
		return true, ErrQuerySyntaxError
	}
	evaluatedStmt := parsedSelectQuery.(*sqlparser.Select)
	if evaluatedStmt.Where != nil {
		if strings.EqualFold(sqlparser.String(forbiddenWhere), sqlparser.String(evaluatedStmt.Where.Expr)) {
			if handler.isForbiddenTableAccess(evaluatedStmt.From, forbiddenTables) {
				if handler.isForbiddenColumnAccess(evaluatedStmt.SelectExprs, forbiddenColumns) {
					return true, nil
				}
			}
		}
	} else {
		if handler.isForbiddenTableAccess(evaluatedStmt.From, forbiddenTables) {
			if handler.isForbiddenColumnAccess(evaluatedStmt.SelectExprs, forbiddenColumns) {
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
	if strings.EqualFold(sqlparser.String(forbiddenColumns), "*") {
		return true
	}
	for _, columnToEvaluate := range columnsToEvaluate {
		for _, forbiddenColumn := range forbiddenColumns {
			if reflect.DeepEqual(columnToEvaluate, forbiddenColumn) {
				return true
			}
		}
	}
	return false
}
