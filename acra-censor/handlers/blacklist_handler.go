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

//NewBlacklistHandler creates new blacklist instance
func NewBlacklistHandler() *BlacklistHandler {
	handler := &BlacklistHandler{}
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.patterns = make([][]sqlparser.SQLNode, 0)
	handler.logger = log.WithField("handler", "blacklist")
	return handler
}

//CheckQuery checks input query
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
			return false, ErrPatternCheckError
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

//Reset resets blacklist to initial state
func (handler *BlacklistHandler) Reset() {
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.patterns = make([][]sqlparser.SQLNode, 0)
	handler.logger = log.WithField("handler", "blacklist")
}

//Release releases all resources
func (handler *BlacklistHandler) Release() {
	handler.Reset()
}

//AddQueries add slice of queries as is to blacklist
func (handler *BlacklistHandler) AddQueries(queries []string) {
	for _, query := range queries {
		handler.queries[query] = true
	}
}

//RemoveQueries removes slice of queries from blacklist
func (handler *BlacklistHandler) RemoveQueries(queries []string) {
	for _, query := range queries {
		delete(handler.queries, query)
	}
}

//AddTables add slice of table names to blacklist
func (handler *BlacklistHandler) AddTables(tableNames []string) {
	for _, tableName := range tableNames {
		handler.tables[tableName] = true
	}
}

//RemoveTables removes slice of table names from blacklist
func (handler *BlacklistHandler) RemoveTables(tableNames []string) {
	for _, tableName := range tableNames {
		delete(handler.tables, tableName)
	}
}

//AddPatterns adds slice of patterns to blacklist
func (handler *BlacklistHandler) AddPatterns(patterns []string) error {
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
	matchOccurred := false
	matchOccurred = handleSelectPattern(queryNodes, patternNodes)
	if matchOccurred {
		return true
	}
	matchOccurred = handleSelectColumnPattern(queryNodes, patternNodes)
	if matchOccurred {
		return true
	}
	matchOccurred = handleSelectWherePattern(queryNodes, patternNodes)
	if matchOccurred {
		return true
	}
	matchOccurred = handleValuePattern(queryNodes, patternNodes)
	if matchOccurred {
		return true
	}
	matchOccurred = handleStarPattern(queryNodes, patternNodes)
	if matchOccurred {
		return true
	}
	//query doesn't match any stored pattern
	return false
}

//handle %%SELECT%% pattern
func handleSelectPattern(queryNodes, patternNodes []sqlparser.SQLNode) bool {
	if reflect.TypeOf(queryNodes[0]) == reflect.TypeOf(patternNodes[0]) {
		if patternNodeSelect, ok := patternNodes[0].(*sqlparser.Select); ok && strings.EqualFold(sqlparser.String(patternNodeSelect.SelectExprs), SelectConfigPlaceholderReplacerPart2) {
			return true
		}
	}
	return false
}

//handle SELECT %%COLUMN%% .. %%COLUMN%% pattern
func handleSelectColumnPattern(queryNodes, patternNodes []sqlparser.SQLNode) bool {
	matchDetected := false
	if len(patternNodes) != len(queryNodes) {
		return false
	}
	for index, patternNode := range patternNodes {
		if index == 0 || reflect.DeepEqual(patternNode, queryNodes[index]) {
			continue
		}
		if patternNodeColName, ok := patternNode.(*sqlparser.ColName); ok && patternNodeColName != nil {
			if strings.EqualFold(patternNodeColName.Name.String(), ColumnConfigPlaceholderReplacer) {
				matchDetected = true
			} else {
				return false
			}
		}
	}
	return matchDetected
}

//handle SELECT a, b from t %%WHERE%% pattern
func handleSelectWherePattern(queryNodes, patternNodes []sqlparser.SQLNode) bool {
	patternWhereDetected := false
	queryWhereDetected := false
	for index, patternNode := range patternNodes {
		if index == 0 || reflect.DeepEqual(queryNodes[index], patternNode) {
			continue
		}
		if patternWhereNode, ok := patternNode.(*sqlparser.Where); ok && patternWhereNode != nil && strings.EqualFold(sqlparser.String(patternWhereNode.Expr), WhereConfigPlaceholderReplacerPart2) {
			patternWhereDetected = true
		}
		if queryWhereNode, ok := queryNodes[index].(*sqlparser.Where); ok && queryWhereNode != nil {
			queryWhereDetected = true
		}
		if queryWhereDetected && patternWhereDetected {
			return true
		}
		return false
	}
	//this is a case when pattern == query
	return true
}

//handle SELECT a, b FROM t1 WHERE userID=%%VALUE%% pattern
func handleValuePattern(queryNodes, patternNodes []sqlparser.SQLNode) bool {
	matchDetected := false
	if len(patternNodes) != len(queryNodes) {
		return false
	}
	for index, patternNode := range patternNodes {
		if index == 0 || reflect.DeepEqual(patternNode, queryNodes[index]) {
			continue
		}
		if patternNodeComparison, ok := patternNode.(*sqlparser.ComparisonExpr); ok && patternNodeComparison != nil {
			if queryNodeComparison, ok := queryNodes[index].(*sqlparser.ComparisonExpr); ok && queryNodeComparison != nil {
				if reflect.DeepEqual(queryNodeComparison.Left, patternNodeComparison.Left) {
					if strings.EqualFold(sqlparser.String(patternNodeComparison.Right), ValueConfigPlaceholderReplacer) {
						matchDetected = true
					}
				}
			}
		}
	}
	return matchDetected
}

//handle SELECT * FROM table %%WHERE%% pattern
func handleStarPattern(queryNodes, patternNodes []sqlparser.SQLNode) bool {
	patternStarDetected := false
	patternWhereDetected := false
	queryWhereDetected := false
	var patternTables sqlparser.TableExprs
	var queryTables sqlparser.TableExprs
	for _, patternNode := range patternNodes {
		if _, ok := patternNode.(*sqlparser.StarExpr); ok {
			patternStarDetected = true
		}
		if patternWhereNode, ok := patternNode.(*sqlparser.Where); ok && patternWhereNode != nil && strings.EqualFold(sqlparser.String(patternWhereNode.Expr), WhereConfigPlaceholderReplacerPart2) {
			patternWhereDetected = true
		}
		if patternSelectStatement, ok := patternNode.(*sqlparser.Select); ok && patternSelectStatement != nil {
			patternTables = patternSelectStatement.From
		}
	}
	for _, queryNode := range queryNodes {
		if queryWhereNode, ok := queryNode.(*sqlparser.Where); ok && queryWhereNode != nil {
			queryWhereDetected = true
		}
		if querySelectStatement, ok := queryNode.(*sqlparser.Select); ok && querySelectStatement != nil {
			queryTables = querySelectStatement.From
		}
	}
	if patternStarDetected {
		if reflect.DeepEqual(patternTables, queryTables) && queryWhereDetected && patternWhereDetected {
			return true
		}
	}
	return false
}
