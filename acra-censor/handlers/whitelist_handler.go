package handlers

import (
	"errors"
	"github.com/xwb1989/sqlparser"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
)

type WhitelistHandler struct {
	queries []string
	tables  []string
	rules   []string
}

func (handler *WhitelistHandler) CheckQuery(query string) (bool, error) {
	//Check queries
	if len(handler.queries) != 0 {
		yes, _ := contains(handler.queries, query)
		if !yes {
			return false, ErrQueryNotInWhitelist
		}
	}
	//Check tables
	if len(handler.tables) != 0 {
		parsedQuery, err := sqlparser.Parse(query)
		if err != nil {
			log.WithError(err).Errorln("Can't parse query in whitelist handler for check")
			return false, ErrQuerySyntaxError
		}
		switch parsedQuery := parsedQuery.(type) {
		case *sqlparser.Select:
			for _, fromStatement := range parsedQuery.From {
				switch fromStatement.(type) {
				case *sqlparser.AliasedTableExpr:
					err = handler.handleAliasedTables(parsedQuery.From)
					if err != nil {
						log.WithError(err).Debugln("error from WhitlistHandler.handleAliasedTables")
						return false, ErrAccessToForbiddenTableWhitelist
					}
					break
				case *sqlparser.JoinTableExpr:
					err = handler.handleJoinedTables(fromStatement.(*sqlparser.JoinTableExpr))
					if err != nil {
						log.WithError(err).Debugln("error from WhitlistHandler.handleJoinedTables")
						return false, ErrAccessToForbiddenTableWhitelist
					}
				case *sqlparser.ParenTableExpr:
					err = handler.handleParenTables(fromStatement.(*sqlparser.ParenTableExpr))
					if err != nil {
						log.WithError(err).Debugln("error from WhitlistHandler.handleParenTables")
						return false, ErrAccessToForbiddenTableWhitelist
					}
				default:
					return false, ErrUnexpectedTypeError
				}
			}
		case *sqlparser.Insert:
			tableIsAllowed := false
			for _, allowedTable := range handler.tables {
				if strings.EqualFold(parsedQuery.Table.Name.String(), allowedTable) {
					tableIsAllowed = true
				}
			}
			if !tableIsAllowed {
				return false, ErrAccessToForbiddenTableWhitelist
			}
		case *sqlparser.Update:
			return false, ErrNotImplemented
		}
	}
	//Check rules
	if len(handler.rules) != 0 {
		violationOccured, err := handler.testRulesViolation(query)
		if err != nil {
			return false, ErrParseSqlRuleWhitelist
		}
		if violationOccured {
			return false, ErrForbiddenSqlStructureWhitelist
		}
	}
	//We do not continue verification because query matches whitelist
	return false, nil
}

func (handler *WhitelistHandler) handleAliasedTables(parsedQuery sqlparser.TableExprs) error {
	allowedTablesCounter := 0
	var err error
	for _, allowedTable := range handler.tables {
		for _, table := range parsedQuery {
			switch table.(type) {
			case *sqlparser.AliasedTableExpr:
				if strings.EqualFold(sqlparser.String(table.(*sqlparser.AliasedTableExpr).Expr), allowedTable) {
					allowedTablesCounter++
				}
				break
			case *sqlparser.JoinTableExpr:
				err = handler.handleJoinedTables(table.(*sqlparser.JoinTableExpr))
				if err != nil {
					return ErrAccessToForbiddenTableWhitelist
				}
				break
			case *sqlparser.ParenTableExpr:
				err = handler.handleParenTables(table.(*sqlparser.ParenTableExpr))
				if err != nil {
					return ErrAccessToForbiddenTableWhitelist
				}
				break
			default:
				return ErrUnexpectedTypeError
			}
			if err != nil {
				return ErrAccessToForbiddenTableWhitelist
			}
		}
	}
	if allowedTablesCounter != len(parsedQuery) {
		return ErrAccessToForbiddenTableWhitelist
	} else {
		return nil
	}
}

func (handler *WhitelistHandler) handleJoinedTables(statement *sqlparser.JoinTableExpr) error {
	var err error
	switch statement.LeftExpr.(type) {
	case *sqlparser.AliasedTableExpr:
		var tables sqlparser.TableExprs
		tables = append(tables, statement.LeftExpr)
		err = handler.handleAliasedTables(tables)
	case *sqlparser.JoinTableExpr:
		err = handler.handleJoinedTables(statement.LeftExpr.(*sqlparser.JoinTableExpr))
	case *sqlparser.ParenTableExpr:
		err = handler.handleParenTables(statement.LeftExpr.(*sqlparser.ParenTableExpr))
	default:
		return ErrUnexpectedTypeError
	}
	if err != nil {
		return err
	}
	switch statement.RightExpr.(type) {
	case *sqlparser.AliasedTableExpr:
		var tables sqlparser.TableExprs
		tables = append(tables, statement.RightExpr)
		err = handler.handleAliasedTables(tables)
	case *sqlparser.JoinTableExpr:
		err = handler.handleJoinedTables(statement.RightExpr.(*sqlparser.JoinTableExpr))
	case *sqlparser.ParenTableExpr:
		err = handler.handleParenTables(statement.RightExpr.(*sqlparser.ParenTableExpr))
	default:
		err = ErrUnexpectedTypeError
	}
	if err != nil {
		return err
	}
	return nil
}

func (handler *WhitelistHandler) handleParenTables(statement *sqlparser.ParenTableExpr) error {
	var err error
	for _, singleExpression := range statement.Exprs {
		switch singleExpression.(type) {
		case *sqlparser.AliasedTableExpr:
			var tables sqlparser.TableExprs
			tables = append(tables, singleExpression)
			err = handler.handleAliasedTables(tables)
		case *sqlparser.JoinTableExpr:
			err = handler.handleJoinedTables(singleExpression.(*sqlparser.JoinTableExpr))
		case *sqlparser.ParenTableExpr:
			err = handler.handleParenTables(singleExpression.(*sqlparser.ParenTableExpr))
		default:
			return ErrUnexpectedTypeError
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (handler *WhitelistHandler) Reset() {
	handler.queries = nil
	handler.tables = nil
	handler.rules = nil
}

func (handler *WhitelistHandler) Release() {
	handler.Reset()
}

func (handler *WhitelistHandler) AddQueries(queries []string) error {
	for _, query := range queries {
		handler.queries = append(handler.queries, query)
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
			log.WithError(err).Errorln("Can't parse query to add rule to whitelist handler")
			return ErrQuerySyntaxError
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
			log.WithError(err).Errorln("Can't parse rule in whitelist handler for test")
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

func (handler *WhitelistHandler) isDangerousSelect(selectQuery string, allowedWhere sqlparser.SQLNode, allowedTables sqlparser.TableExprs, allowedColumns sqlparser.SelectExprs) (bool, error) {
	parsedSelectQuery, err := sqlparser.Parse(selectQuery)
	if err != nil {
		log.WithError(err).Errorln("Can't parse query in whitelist handler to check is it dangerous select")
		return true, ErrQuerySyntaxError
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

func (handler *WhitelistHandler) handleJoinTables(expr sqlparser.TableExprs) error {
	//stub
	return nil
}
