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
	"github.com/cossacklabs/acra/sqlparser"
	log "github.com/sirupsen/logrus"
)

// AllowHandler allows query/pattern/table and restricts/forbids everything else
type AllowHandler struct {
	queries  map[string]bool
	tables   map[string]bool
	patterns []sqlparser.Statement
	logger   *log.Entry
	parser   *sqlparser.Parser
}

// NewAllowHandler creates new whitelist instance
func NewAllowHandler(parser *sqlparser.Parser) *AllowHandler {
	handler := &AllowHandler{}
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.patterns = make([]sqlparser.Statement, 0)
	handler.logger = log.WithField("handler", "allow")
	handler.parser = parser
	return handler
}

// CheckQuery checks each query, returns false and error if query is not whitelisted or
// if query tries to access to non-whitelisted table
func (handler *AllowHandler) CheckQuery(normalizedQuery string, parsedQuery sqlparser.Statement) (bool, error) {
	// skip unparsed queries
	if parsedQuery == nil {
		return true, nil
	}
	//Check exact queries
	if len(handler.queries) != 0 {
		queryMatch := common.CheckExactQueriesMatch(normalizedQuery, handler.queries)
		if queryMatch {
			return false, nil
		}
	}
	//Check tables
	if len(handler.tables) != 0 {
		_, allTablesInWhitelist := common.CheckTableNamesMatch(parsedQuery, handler.tables)
		if allTablesInWhitelist {
			return false, nil
		}
	}
	//Check patterns
	if len(handler.patterns) != 0 {
		matchingOccurred := common.CheckPatternsMatching(handler.patterns, parsedQuery)
		if matchingOccurred {
			return false, nil
		}
	}
	return true, nil
}

// Reset resets whitelist to initial state
func (handler *AllowHandler) Reset() {
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.patterns = nil
}

// Release releases all resources
func (handler *AllowHandler) Release() {
	handler.Reset()
}

// AddQueries normalizes and adds queries to the list that should be whitelisted
func (handler *AllowHandler) AddQueries(queries []string) error {
	for _, query := range queries {
		normalizedQuery, _, _, err := handler.parser.HandleRawSQLQuery(query)
		if err != nil {
			handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).Errorln("Can't add queries")
			return err
		}
		handler.queries[normalizedQuery] = true
	}
	return nil
}

// RemoveQueries removes queries from the list that should be whitelisted
func (handler *AllowHandler) RemoveQueries(queries []string) error {
	for _, query := range queries {
		normalizedQuery, _, _, err := handler.parser.HandleRawSQLQuery(query)
		if err != nil {
			handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).Errorln("Can't remove queries")
			return err
		}
		delete(handler.queries, normalizedQuery)
	}
	return nil
}

// AddTables adds tables that should be whitelisted
func (handler *AllowHandler) AddTables(tableNames []string) {
	for _, tableName := range tableNames {
		handler.tables[tableName] = true
	}
}

// RemoveTables removes whitelisted tables
func (handler *AllowHandler) RemoveTables(tableNames []string) {
	for _, tableName := range tableNames {
		delete(handler.tables, tableName)
	}
}

// AddPatterns adds patterns that should be whitelisted
func (handler *AllowHandler) AddPatterns(patterns []string) error {
	parsedPatterns, err := common.ParsePatterns(patterns, handler.parser)
	if err != nil {
		handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).Errorln("Can't add patterns")
		return err
	}
	handler.patterns = parsedPatterns
	return nil
}
