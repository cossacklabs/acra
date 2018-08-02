package handlers

import (
	"github.com/cossacklabs/acra/logging"
	"github.com/xwb1989/sqlparser"
	"strings"

	log "github.com/sirupsen/logrus"
)

// WhitelistHandler shows handler structure
type WhitelistHandler struct {
	queries  map[string]bool
	tables   map[string]bool
	patterns [][]sqlparser.SQLNode
	logger   *log.Entry
}

// NewWhitelistHandler creates new whitelist instance
func NewWhitelistHandler() *WhitelistHandler {
	handler := &WhitelistHandler{}
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.patterns = make([][]sqlparser.SQLNode, 0)
	handler.logger = log.WithField("handler", "whitelist")
	return handler
}

// CheckQuery checks each query, returns false and error if query is not whitelisted or
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
	//Check patterns
	if len(handler.patterns) != 0 {
		matchingOccurred, err := checkPatternsMatching(handler.patterns, query)
		if err != nil {
			return false, ErrPatternCheckError
		}
		if !matchingOccurred {
			return false, ErrWhitelistPatternMismatch
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

// Reset resets whitelist to initial state
func (handler *WhitelistHandler) Reset() {
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.patterns = nil
}

// Release releases all resources
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

// AddPatterns adds patterns that should be whitelisted
func (handler *WhitelistHandler) AddPatterns(patterns []string) error {
	placeholders := []string{SelectConfigPlaceholder, ColumnConfigPlaceholder, WhereConfigPlaceholder, ValueConfigPlaceholder}
	replacers := []string{SelectConfigPlaceholderReplacer, ColumnConfigPlaceholderReplacer, WhereConfigPlaceholderReplacer, ValueConfigPlaceholderReplacer}
	patternValue := ""
	for _, pattern := range patterns {
		patternValue = pattern
		for index, placeholder := range placeholders {
			patternValue = strings.Replace(patternValue, placeholder, replacers[index], -1)
		}
		statement, err := sqlparser.Parse(patternValue)
		if err != nil {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).WithError(err).Errorln("Can't add specified pattern in blacklist handler")
			return ErrPatternSyntaxError
		}
		var newPatternNodes []sqlparser.SQLNode
		sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
			newPatternNodes = append(newPatternNodes, node)
			return true, nil
		}, statement)
		handler.patterns = append(handler.patterns, newPatternNodes)
	}
	return nil
}
