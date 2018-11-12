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
	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"
	"github.com/xwb1989/sqlparser"
)

// WhitelistHandler allows query/pattern/table and restricts/forbids everything else
type WhitelistHandler struct {
	queries  map[string]bool
	tables   map[string]bool
	patterns []sqlparser.Statement
	logger   *log.Entry
}

// NewWhitelistHandler creates new whitelist instance
func NewWhitelistHandler() *WhitelistHandler {
	handler := &WhitelistHandler{}
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.patterns = make([]sqlparser.Statement, 0)
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
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).WithError(err).Errorln("Query has been blocked by whitelist [tables]. Parsing error")
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
				handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(ErrAccessToForbiddenTableWhitelist).Errorln("Query has been blocked by whitelist [tables]")
				return false, ErrAccessToForbiddenTableWhitelist
			}
		}
	}
	//Check patterns
	if len(handler.patterns) != 0 {
		matchingOccurred, err := checkPatternsMatching(handler.patterns, query)
		if err != nil {
			handler.logger.WithError(err).Debugln("Error from WhitelistHandler [patterns]")
			if err == ErrQuerySyntaxError {
				return false, ErrQuerySyntaxError
			}
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
				handler.logger.WithError(ErrAccessToForbiddenTableWhitelist).Debugln("Error from WhitelistHandler.handleAliasedTables. [evaluated table not found in whitelist]")
				return ErrAccessToForbiddenTableWhitelist
			}
		case *sqlparser.JoinTableExpr:
			err = handler.handleJoinedTables(table.(*sqlparser.JoinTableExpr))
			if err != nil {
				handler.logger.WithError(err).Debugln("Error from WhitelistHandler.handleAliasedTables [joined table]")
				return ErrAccessToForbiddenTableWhitelist
			}
		case *sqlparser.ParenTableExpr:
			err = handler.handleParenTables(table.(*sqlparser.ParenTableExpr))
			if err != nil {
				handler.logger.WithError(err).Debugln("Error from WhitelistHandler.handleAliasedTables [paren table]")
				return ErrAccessToForbiddenTableWhitelist
			}
		default:
			handler.logger.WithError(ErrUnexpectedTypeError).Debugln("Error from WhitelistHandler.handleAliasedTables [unexpected type of table]")
			return ErrUnexpectedTypeError
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
		handler.logger.WithError(err).Debugln("Error from WhitelistHandler.handleJoinedTables - left expr. [aliased table]")
	case *sqlparser.JoinTableExpr:
		err = handler.handleJoinedTables(statement.LeftExpr.(*sqlparser.JoinTableExpr))
		handler.logger.WithError(err).Debugln("Error from WhitelistHandler.handleJoinedTables - left expr. [joined table]")
	case *sqlparser.ParenTableExpr:
		err = handler.handleParenTables(statement.LeftExpr.(*sqlparser.ParenTableExpr))
		handler.logger.WithError(err).Debugln("Error from WhitelistHandler.handleJoinedTables - left expr. [paren table]")
	default:
		handler.logger.WithError(ErrUnexpectedTypeError).Debugln("Error from WhitelistHandler.handleJoinedTables - left expr. [unexpected type of table]")
		return ErrUnexpectedTypeError
	}
	if err != nil {
		//this err will be already logged
		return err
	}
	switch statement.RightExpr.(type) {
	case *sqlparser.AliasedTableExpr:
		var tables sqlparser.TableExprs
		tables = append(tables, statement.RightExpr)
		err = handler.handleAliasedTables(tables)
		handler.logger.WithError(err).Debugln("Error from WhitelistHandler.handleJoinedTables - right expr. [aliased table]")
	case *sqlparser.JoinTableExpr:
		err = handler.handleJoinedTables(statement.RightExpr.(*sqlparser.JoinTableExpr))
		handler.logger.WithError(err).Debugln("Error from WhitelistHandler.handleJoinedTables - right expr. [joined table]")
	case *sqlparser.ParenTableExpr:
		err = handler.handleParenTables(statement.RightExpr.(*sqlparser.ParenTableExpr))
		handler.logger.WithError(err).Debugln("Error from WhitelistHandler.handleJoinedTables - right expr. [paren table]")
	default:
		handler.logger.WithError(ErrUnexpectedTypeError).Debugln("Error from WhitelistHandler.handleJoinedTables - right expr. [unexpected type of table]")
		err = ErrUnexpectedTypeError
	}
	if err != nil {
		//this error will be already logged
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
			handler.logger.WithError(err).Debugln("Error from WhitelistHandler.handleParenTables. [aliased table]")
		case *sqlparser.JoinTableExpr:
			err = handler.handleJoinedTables(singleExpression.(*sqlparser.JoinTableExpr))
			handler.logger.WithError(err).Debugln("Error from WhitelistHandler.handleParenTables. [joined table]")
		case *sqlparser.ParenTableExpr:
			err = handler.handleParenTables(singleExpression.(*sqlparser.ParenTableExpr))
			handler.logger.WithError(err).Debugln("Error from WhitelistHandler.handleParenTables. [paren table]")
		default:
			handler.logger.WithError(ErrUnexpectedTypeError).Debugln("Error from WhitelistHandler.handleParenTables. [unexpected type of table]")
			return ErrUnexpectedTypeError
		}
		if err != nil {
			//this error will be already logged
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

// AddQueries normalizes and adds queries to the list that should be whitelisted
func (handler *WhitelistHandler) AddQueries(queries []string) {
	for _, query := range queries {
		normalizedQuery, _, err := NormalizeAndRedactSQLQuery(query)
		if err != nil {
			continue
		}
		handler.queries[normalizedQuery] = true
	}
}

// RemoveQueries removes queries from the list that should be whitelisted
func (handler *WhitelistHandler) RemoveQueries(queries []string) {
	for _, query := range queries {
		normalizedQuery, _, err := NormalizeAndRedactSQLQuery(query)
		if err != nil {
			continue
		}
		delete(handler.queries, normalizedQuery)
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
	parsedPatterns, err := ParsePatterns(patterns)
	if err != nil {
		return err
	}
	handler.patterns = parsedPatterns
	return nil
}
