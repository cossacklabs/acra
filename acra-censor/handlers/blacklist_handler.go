/*
Copyright 2018, Cossack Labs Limited

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

package handlers

import (
	"github.com/cossacklabs/acra/acra-censor/common"
	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"
	"github.com/xwb1989/sqlparser"
)

// BlacklistHandler allows everything and forbids specific query/pattern/table
type BlacklistHandler struct {
	queries  map[string]bool
	tables   map[string]bool
	patterns []sqlparser.Statement
	logger   *log.Entry
}

// NewBlacklistHandler creates new blacklist instance
func NewBlacklistHandler() *BlacklistHandler {
	handler := &BlacklistHandler{}
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.patterns = make([]sqlparser.Statement, 0)
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
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(common.ErrQueryInBlacklist).Errorln("Query has been blocked by blacklist [queries]")
			return false, common.ErrQueryInBlacklist
		}
	}
	//Check tables
	if len(handler.tables) != 0 {
		parsedQuery, err := sqlparser.Parse(query)
		if err != nil {
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).WithError(err).Errorln("Query has been blocked by blacklist [tables]. Parsing error")
			return false, common.ErrQuerySyntaxError
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
						return false, common.ErrAccessToForbiddenTableBlacklist
					}
					break
				case *sqlparser.JoinTableExpr:
					err = handler.handleJoinedTables(fromStatement.(*sqlparser.JoinTableExpr))
					if err != nil {
						log.WithError(err).Debugln("Error from BlacklistHandler.handleJoinedTables")
						handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(err).Errorln("Query has been blocked by blacklist [tables]")
						return false, common.ErrAccessToForbiddenTableBlacklist
					}
					break
				case *sqlparser.ParenTableExpr:
					err = handler.handleParenTables(fromStatement.(*sqlparser.ParenTableExpr))
					if err != nil {
						log.WithError(err).Debugln("Error from BlacklistHandler.handleParenTables")
						handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(err).Errorln("Query has been blocked by blacklist [tables]")
						return false, common.ErrAccessToForbiddenTableBlacklist
					}
					break
				default:
					return false, common.ErrUnexpectedTypeError
				}
			}
		case *sqlparser.Insert:
			if handler.tables[parsedQuery.Table.Name.String()] {
				handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(common.ErrAccessToForbiddenTableBlacklist).Errorln("Query has been blocked by blacklist [tables]")
				return false, common.ErrAccessToForbiddenTableBlacklist
			}
		}
	}
	//Check patterns
	if len(handler.patterns) != 0 {
		matchingOccurred, err := common.CheckPatternsMatching(handler.patterns, query)
		if err != nil {
			handler.logger.WithError(err).Debugln("Error from BlacklistHandler [patterns]")
			if err == common.ErrQuerySyntaxError {
				return false, common.ErrQuerySyntaxError
			}
			return false, common.ErrPatternCheckError
		}
		if matchingOccurred {
			return false, common.ErrBlacklistPatternMatch
		}
	}
	return true, nil
}

func (handler *BlacklistHandler) handleAliasedTables(statement *sqlparser.AliasedTableExpr) error {
	if handler.tables[sqlparser.String(statement.Expr)] {
		handler.logger.WithError(common.ErrAccessToForbiddenTableBlacklist).Debugln("Error from BlacklistHandler.handleAliasedTables. [evaluated table found in blacklist]")
		return common.ErrAccessToForbiddenTableBlacklist
	}
	return nil
}

func (handler *BlacklistHandler) handleJoinedTables(statement *sqlparser.JoinTableExpr) error {
	var err error
	switch statement.LeftExpr.(type) {
	case *sqlparser.AliasedTableExpr:
		err = handler.handleAliasedTables(statement.LeftExpr.(*sqlparser.AliasedTableExpr))
		handler.logger.WithError(err).Debugln("Error from BlacklistHandler.handleJoinedTables - left expr. [aliased table]")
	case *sqlparser.JoinTableExpr:
		err = handler.handleJoinedTables(statement.LeftExpr.(*sqlparser.JoinTableExpr))
		handler.logger.WithError(err).Debugln("Error from BlacklistHandler.handleJoinedTables - left expr. [joined table]")
	case *sqlparser.ParenTableExpr:
		err = handler.handleParenTables(statement.LeftExpr.(*sqlparser.ParenTableExpr))
		handler.logger.WithError(err).Debugln("Error from BlacklistHandler.handleJoinedTables - left expr. [paren table]")
	default:
		handler.logger.WithError(common.ErrUnexpectedTypeError).Debugln("Error from BlacklistHandler.handleJoinedTables - left expr. [unexpected type of table]")
		return common.ErrUnexpectedTypeError
	}
	if err != nil {
		//this err will be already logged
		return err
	}
	switch statement.RightExpr.(type) {
	case *sqlparser.AliasedTableExpr:
		err = handler.handleAliasedTables(statement.RightExpr.(*sqlparser.AliasedTableExpr))
		handler.logger.WithError(err).Debugln("Error from BlacklistHandler.handleJoinedTables - right expr. [aliased table]")
	case *sqlparser.JoinTableExpr:
		err = handler.handleJoinedTables(statement.RightExpr.(*sqlparser.JoinTableExpr))
		handler.logger.WithError(err).Debugln("Error from BlacklistHandler.handleJoinedTables - right expr. [joined table]")
	case *sqlparser.ParenTableExpr:
		err = handler.handleParenTables(statement.RightExpr.(*sqlparser.ParenTableExpr))
		handler.logger.WithError(err).Debugln("Error from BlacklistHandler.handleJoinedTables - right expr. [paren table]")
	default:
		handler.logger.WithError(common.ErrUnexpectedTypeError).Debugln("Error from BlacklistHandler.handleJoinedTables - right expr. [unexpected type of table]")
		err = common.ErrUnexpectedTypeError
	}
	if err != nil {
		//this err will be already logged
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
			handler.logger.WithError(err).Debugln("Error from BlacklistHandler.handleParenTables. [aliased table]")
		case *sqlparser.JoinTableExpr:
			err = handler.handleJoinedTables(singleExpression.(*sqlparser.JoinTableExpr))
			handler.logger.WithError(err).Debugln("Error from BlacklistHandler.handleParenTables. [joined table]")
		case *sqlparser.ParenTableExpr:
			err = handler.handleParenTables(singleExpression.(*sqlparser.ParenTableExpr))
			handler.logger.WithError(err).Debugln("Error from BlacklistHandler.handleParenTables. [paren table]")
		default:
			handler.logger.WithError(common.ErrUnexpectedTypeError).Debugln("Error from BlacklistHandler.handleParenTables. [unexpected type of table]")
			return common.ErrUnexpectedTypeError
		}
		if err != nil {
			//this err will be already logged
			return err
		}
	}
	return nil
}

// Reset resets blacklist to initial state
func (handler *BlacklistHandler) Reset() {
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.patterns = make([]sqlparser.Statement, 0)
	handler.logger = log.WithField("handler", "blacklist")
}

// Release releases all resources
func (handler *BlacklistHandler) Release() {
	handler.Reset()
}

// AddQueries normalizes and adds queries to the list that should be blacklisted
func (handler *BlacklistHandler) AddQueries(queries []string) {
	for _, query := range queries {
		normalizedQuery, _, err := common.NormalizeAndRedactSQLQuery(query)
		if err != nil {
			continue
		}
		handler.queries[normalizedQuery] = true
	}
}

// RemoveQueries removes queries from the list that should be blacklisted
func (handler *BlacklistHandler) RemoveQueries(queries []string) {
	for _, query := range queries {
		normalizedQuery, _, err := common.NormalizeAndRedactSQLQuery(query)
		if err != nil {
			continue
		}
		delete(handler.queries, normalizedQuery)
	}
}

// AddTables adds tables that should be blacklisted
func (handler *BlacklistHandler) AddTables(tableNames []string) {
	for _, tableName := range tableNames {
		handler.tables[tableName] = true
	}
}

// RemoveTables removes blacklisted tables
func (handler *BlacklistHandler) RemoveTables(tableNames []string) {
	for _, tableName := range tableNames {
		delete(handler.tables, tableName)
	}
}

// AddPatterns adds patterns that should be blacklisted
func (handler *BlacklistHandler) AddPatterns(patterns []string) error {
	parsedPatterns, err := common.ParsePatterns(patterns)
	if err != nil {
		return err
	}
	handler.patterns = parsedPatterns
	return nil
}
