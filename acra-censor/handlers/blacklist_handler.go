package handlers

import (
	"github.com/cossacklabs/acra/logging"
	"github.com/xwb1989/sqlparser"
	"strings"

	log "github.com/sirupsen/logrus"
	"reflect"
)

type BlacklistHandler struct {
	queries  map[string]bool
	tables   map[string]bool
	patterns [][]sqlparser.SQLNode
	logger   *log.Entry
}

func NewBlacklistHandler() *BlacklistHandler {
	handler := &BlacklistHandler{}
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.patterns = make([][]sqlparser.SQLNode, 0)
	handler.logger = log.WithField("handler", "blacklist")
	return handler
}

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
	//Check patterns
	if len(handler.patterns) != 0 {
		matchingOccurred, err := handler.checkPatternsMatching(query)
		if err != nil {
			return false, ErrPatternSyntaxError
		}
		if matchingOccurred {
			return false, ErrBlacklistPatternMatch
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

func (handler *BlacklistHandler) Reset() {
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.patterns = make([][]sqlparser.SQLNode, 0)
	handler.logger = log.WithField("handler", "blacklist")
}

func (handler *BlacklistHandler) Release() {
	handler.Reset()
}

func (handler *BlacklistHandler) AddQueries(queries []string) {
	for _, query := range queries {
		handler.queries[query] = true
	}
}

func (handler *BlacklistHandler) RemoveQueries(queries []string) {
	for _, query := range queries {
		delete(handler.queries, query)
	}
}

func (handler *BlacklistHandler) AddTables(tableNames []string) {
	for _, tableName := range tableNames {
		handler.tables[tableName] = true
	}
}

func (handler *BlacklistHandler) RemoveTables(tableNames []string) {
	for _, tableName := range tableNames {
		delete(handler.tables, tableName)
	}
}

func (handler *BlacklistHandler) AddPatterns(patterns []string) error {
	placeholders := []string{SelectConfigPlaceholder}
	replacers := []string{SelectConfigPlaceholderReplacer}

	patternValue := ""
	for _, pattern := range patterns {
		patternValue = pattern
		for index, placeholder := range placeholders {
			patternValue = strings.Replace(patternValue, placeholder, replacers[index], -1)
		}
		statement, err := sqlparser.Parse(patternValue)
		//fmt.Println(sqlparser.String(statement))
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

func (handler *BlacklistHandler) checkPatternsMatching(query string) (bool, error) {
	var queryNodes []sqlparser.SQLNode
	statement, err := sqlparser.Parse(query)
	if err != nil {
		return false, ErrQuerySyntaxError
	}
	sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
		queryNodes = append(queryNodes, node)
		return true, nil
	}, statement)
	for _, singlePatternNodes := range handler.patterns {
		if checkSinglePatternMatch(queryNodes, singlePatternNodes) {
			return true, nil
		}
	}
	return false, nil
}
func checkSinglePatternMatch(queryNodes []sqlparser.SQLNode, patternNodes []sqlparser.SQLNode) bool {
	//handle %%SELECT%% pattern
	var emptySelect *sqlparser.Select
	if reflect.TypeOf(queryNodes[0]) == reflect.TypeOf(emptySelect) && reflect.TypeOf(patternNodes[0]) == reflect.TypeOf(emptySelect) {
		if strings.EqualFold(sqlparser.String(patternNodes[0].(*sqlparser.Select).SelectExprs), SelectConfigPlaceholderReplacerPart2) {
			return true
		}
	}
	return false
}
