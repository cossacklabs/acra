package handlers

import (
	"errors"
	"github.com/cossacklabs/acra/logging"
	"github.com/xwb1989/sqlparser"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
)

// BlacklistHandler shows handler structure
type BlacklistHandler struct {
	queries map[string]bool
	tables  map[string]bool
	rules   []string
	logger  *log.Entry
}

// NewBlacklistHandler creates new blacklist handler
func NewBlacklistHandler() *BlacklistHandler {
	handler := &BlacklistHandler{}
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.logger = log.WithField("handler", "blacklist")
	return handler
}

// CheckQuery checks each query, returns false and error if query is blacklisted or
// if query tries to access to forbidden table
func (handler *BlacklistHandler) CheckQuery(query string) (bool, error) {
	//Check queries
	if len(handler.queries) != 0 {
		//Check that query is not in blacklist
		if handler.queries[query] {
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(ErrQueryInBlacklist).Errorln("Query has been blocked by blacklist [queries]")
			return false, ErrQueryInBlacklist
		}
	}
	//Check tables
	if len(handler.tables) != 0 {
		parsedQuery, err := sqlparser.Parse(query)
		if err != nil {
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).WithError(ErrQuerySyntaxError).Errorln("Query has been blocked by blacklist [tables]. Parsing error")
			return false, ErrQuerySyntaxError
		}
		switch parsedQuery := parsedQuery.(type) {
		case *sqlparser.Select:
			for _, fromStatement := range parsedQuery.From {
				switch fromStatement.(type) {
				case *sqlparser.AliasedTableExpr:
					err = handler.handleAliasedTables(fromStatement.(*sqlparser.AliasedTableExpr))
					if err != nil {
						log.WithError(err).Debugln("Error from BlacklistHandler.handleAliasedTables")
						handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(err).Errorln("Query has been blocked by blacklist [tables]")
						return false, ErrAccessToForbiddenTableBlacklist
					}
					break
				case *sqlparser.JoinTableExpr:
					err = handler.handleJoinedTables(fromStatement.(*sqlparser.JoinTableExpr))
					if err != nil {
						log.WithError(err).Debugln("Error from BlacklistHandler.handleJoinedTables")
						handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(err).Errorln("Query has been blocked by blacklist [tables]")
						return false, ErrAccessToForbiddenTableBlacklist
					}
					break
				case *sqlparser.ParenTableExpr:
					err = handler.handleParenTables(fromStatement.(*sqlparser.ParenTableExpr))
					if err != nil {
						log.WithError(err).Debugln("Error from BlacklistHandler.handleParenTables")
						handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(err).Errorln("Query has been blocked by blacklist [tables]")
						return false, ErrAccessToForbiddenTableBlacklist
					}
					break
				default:
					return false, ErrUnexpectedTypeError
				}
			}
		case *sqlparser.Insert:
			if handler.tables[parsedQuery.Table.Name.String()] {
				handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(ErrAccessToForbiddenTableBlacklist).Errorln("Query has been blocked by blacklist [tables]")
				return false, ErrAccessToForbiddenTableBlacklist
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
			return false, ErrParseSQLRuleBlacklist
		}
		if violationOccured {
			return false, ErrForbiddenSQLStructureBlacklist
		}
	}
	return true, nil
}

func (handler *BlacklistHandler) handleAliasedTables(statement *sqlparser.AliasedTableExpr) error {
	if handler.tables[sqlparser.String(statement.Expr)] {
		return ErrAccessToForbiddenTableBlacklist
	} else {
		return nil
	}
}

func (handler *BlacklistHandler) handleJoinedTables(statement *sqlparser.JoinTableExpr) error {
	var err error
	switch statement.LeftExpr.(type) {
	case *sqlparser.AliasedTableExpr:
		err = handler.handleAliasedTables(statement.LeftExpr.(*sqlparser.AliasedTableExpr))
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
		err = handler.handleAliasedTables(statement.RightExpr.(*sqlparser.AliasedTableExpr))
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

func (handler *BlacklistHandler) handleParenTables(statement *sqlparser.ParenTableExpr) error {
	var err error
	for _, singleExpression := range statement.Exprs {
		switch singleExpression.(type) {
		case *sqlparser.AliasedTableExpr:
			err = handler.handleAliasedTables(singleExpression.(*sqlparser.AliasedTableExpr))
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

// Reset blacklist rules
func (handler *BlacklistHandler) Reset() {
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.rules = nil
}

// Release / reset blacklist rules
func (handler *BlacklistHandler) Release() {
	handler.Reset()
}

// AddQueries adds queries to the list that should be blacklisted
func (handler *BlacklistHandler) AddQueries(queries []string) {
	for _, query := range queries {
		handler.queries[query] = true
	}
}

// RemoveQueries removes queries from the list that should be blacklisted
func (handler *BlacklistHandler) RemoveQueries(queries []string) {
	for _, query := range queries {
		delete(handler.queries, query)
	}
}

// AddTables adds tables that should be forbidden
func (handler *BlacklistHandler) AddTables(tableNames []string) {
	for _, tableName := range tableNames {
		handler.tables[tableName] = true
	}
}

// RemoveTables removes forbidden tables
func (handler *BlacklistHandler) RemoveTables(tableNames []string) {
	for _, tableName := range tableNames {
		delete(handler.tables, tableName)
	}
}

// AddRules adds rules that should be blocked
func (handler *BlacklistHandler) AddRules(rules []string) error {
	for _, rule := range rules {
		handler.rules = append(handler.rules, rule)
		_, err := sqlparser.Parse(rule)
		if err != nil {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).WithError(err).Errorln("Can't parse query to add rule to blacklist handler")
			return ErrQuerySyntaxError
		}
	}
	handler.rules = removeDuplicates(handler.rules)
	return nil
}

// RemoveRules removes rules that should be blocked
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
		return true, errors.New("Non-select queries are not supported")
	}
	//parse one rule and get forbidden tables and columns for specific 'where' clause
	var whereClause sqlparser.SQLNode
	var tables sqlparser.TableExprs
	var columns sqlparser.SelectExprs
	//Parse each rule and then test query
	for _, rule := range handler.rules {
		parsedRule, err := sqlparser.Parse(rule)
		if err != nil {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).WithError(err).Errorln("Can't parse rule in blacklist handler for test")
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
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).WithError(err).Errorln("Can't parse query in blacklist handler to check is it dangerous select")
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
