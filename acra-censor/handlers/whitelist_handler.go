package handlers

import (
	"errors"
	"github.com/cossacklabs/acra/logging"
	"github.com/xwb1989/sqlparser"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
)

// WhitelistHandler shows handler structure
type WhitelistHandler struct {
	queries map[string]bool
	tables  map[string]bool
	rules   []string
	logger  *log.Entry
}

// NewWhitelistHandler creates new white handler
func NewWhitelistHandler() *WhitelistHandler {
	handler := &WhitelistHandler{}
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.logger = log.WithField("handler", "whitelist")
	return handler
}

// CheckQuery checks each query, returns false and error if query is not in a white list or
// if query tries to access to non-whitelisted table
func (handler *WhitelistHandler) CheckQuery(query string) (bool, error) {
	//Check queries
	if len(handler.queries) != 0 {
		//Check that query is in whitelist
		if !handler.queries[query] {
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(ErrQueryNotInWhitelist).Errorln("Query has been blocked by whitelist [queries]")
			return false, ErrQueryNotInWhitelist
		}
	}
	//Check tables
	if len(handler.tables) != 0 {
		parsedQuery, err := sqlparser.Parse(query)
		if err != nil {
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).WithError(ErrQuerySyntaxError).Errorln("Query has been blocked by whitelist [tables]. Parsing error")
			return false, ErrQuerySyntaxError
		}
		switch parsedQuery := parsedQuery.(type) {
		case *sqlparser.Select:
			for _, fromStatement := range parsedQuery.From {
				switch fromStatement.(type) {
				case *sqlparser.AliasedTableExpr:
					err = handler.handleAliasedTables(parsedQuery.From)
					if err != nil {
						handler.logger.WithError(err).Debugln("Error from WhitelistHandler.handleAliasedTables")
						handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(err).Errorln("Query has been blocked by whitelist [tables]")
						return false, ErrAccessToForbiddenTableWhitelist
					}
					break
				case *sqlparser.JoinTableExpr:
					err = handler.handleJoinedTables(fromStatement.(*sqlparser.JoinTableExpr))
					if err != nil {
						handler.logger.WithError(err).Debugln("Error from WhitelistHandler.handleJoinedTables")
						handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(err).Errorln("Query has been blocked by whitelist [tables]")
						return false, ErrAccessToForbiddenTableWhitelist
					}
				case *sqlparser.ParenTableExpr:
					err = handler.handleParenTables(fromStatement.(*sqlparser.ParenTableExpr))
					if err != nil {
						handler.logger.WithError(err).Debugln("Error from WhitelistHandler.handleParenTables")
						handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(err).Errorln("Query has been blocked by whitelist [tables]")
						return false, ErrAccessToForbiddenTableWhitelist
					}
				default:
					return false, ErrUnexpectedTypeError
				}
			}
		case *sqlparser.Insert:
			tableIsAllowed := false
			if handler.tables[parsedQuery.Table.Name.String()] {
				tableIsAllowed = true
			}
			if !tableIsAllowed {
				handler.logger.WithError(err).Debugln("Error from WhitelistHandler [insert]")
				handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(ErrAccessToForbiddenTableWhitelist).Errorln("Query has been blocked by blacklist [tables]")
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
			return false, ErrParseSQLRuleWhitelist
		}
		if violationOccured {
			return false, ErrForbiddenSQLStructureWhitelist
		}
	}
	//We do not continue verification because query matches whitelist
	return false, nil
}

func (handler *WhitelistHandler) handleAliasedTables(parsedQuery sqlparser.TableExprs) error {
	var err error
	for _, table := range parsedQuery {
		switch table.(type) {
		case *sqlparser.AliasedTableExpr:
			if !handler.tables[sqlparser.String(table.(*sqlparser.AliasedTableExpr).Expr)] {
				return ErrAccessToForbiddenTableWhitelist
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
	return nil
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

// Reset whitelist rules
func (handler *WhitelistHandler) Reset() {
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.rules = nil
}

// Release / reset whitelist rules
func (handler *WhitelistHandler) Release() {
	handler.Reset()
}

// AddQueries adds queries to the list that should be whitelisted
func (handler *WhitelistHandler) AddQueries(queries []string) {
	for _, query := range queries {
		handler.queries[query] = true
	}
}

// RemoveQueries removes queries from the list that should be whitelisted
func (handler *WhitelistHandler) RemoveQueries(queries []string) {
	for _, query := range queries {
		delete(handler.queries, query)
	}
}

// AddTables adds tables that should be whitelisted
func (handler *WhitelistHandler) AddTables(tableNames []string) {
	for _, tableName := range tableNames {
		handler.tables[tableName] = true
	}
}

// RemoveTables removes whitelisted tables
func (handler *WhitelistHandler) RemoveTables(tableNames []string) {
	for _, tableName := range tableNames {
		delete(handler.tables, tableName)
	}
}

// AddRules adds rules that should be whitelisted
func (handler *WhitelistHandler) AddRules(rules []string) error {
	for _, rule := range rules {
		handler.rules = append(handler.rules, rule)
		_, err := sqlparser.Parse(rule)
		if err != nil {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).WithError(err).Errorln("Can't parse query to add rule to whitelist handler")
			return ErrQuerySyntaxError
		}
	}
	handler.rules = removeDuplicates(handler.rules)
	return nil
}

// RemoveRules removes rules that should be whitelisted
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
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).WithError(err).Errorln("Can't parse rule in whitelist handler for test")
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
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).WithError(err).Errorln("Can't parse query in whitelist handler to check is it dangerous select")
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
