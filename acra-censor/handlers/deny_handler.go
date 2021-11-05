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

// DenyHandler allows everything and forbids specific query/pattern/table
type DenyHandler struct {
	queries  map[string]bool
	tables   map[string]bool
	patterns []sqlparser.Statement
	logger   *log.Entry
	parser   *sqlparser.Parser
}

// NewDenyHandler creates new blacklist instance
func NewDenyHandler(parser *sqlparser.Parser) *DenyHandler {
	handler := &DenyHandler{}
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.patterns = make([]sqlparser.Statement, 0)
	handler.logger = log.WithField("handler", "blacklist")
	handler.parser = parser
	return handler
}

// CheckQuery checks each query, returns false and error if query is blacklisted or
// if query tries to access to forbidden table
func (handler *DenyHandler) CheckQuery(normalizedQuery string, parsedQuery sqlparser.Statement) (bool, error) {
	// skip unparsed queries
	if parsedQuery == nil {
		return true, nil
	}
	//Check exact queries
	if len(handler.queries) != 0 {
		queryMatch := common.CheckExactQueriesMatch(normalizedQuery, handler.queries)
		if queryMatch {
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(common.ErrDenyByQueryError).Errorln("Query has been blocked by DENY [queries]")
			return false, common.ErrDenyByQueryError
		}
	}
	//Check tables
	if len(handler.tables) != 0 {
		atLeastOneTableInBlacklist, _ := common.CheckTableNamesMatch(parsedQuery, handler.tables)
		if atLeastOneTableInBlacklist {
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(common.ErrDenyByQueryError).Errorln("Query has been blocked by DENY [tables]")
			return false, common.ErrDenyByTableError
		}
	}
	//Check patterns
	if len(handler.patterns) != 0 {
		matchingOccurred := common.CheckPatternsMatching(handler.patterns, parsedQuery)
		if matchingOccurred {
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(common.ErrDenyByQueryError).Errorln("Query has been blocked by DENY [patterns]")
			return false, common.ErrDenyByPatternError
		}
	}
	return true, nil
}

// Reset resets blacklist to initial state
func (handler *DenyHandler) Reset() {
	handler.queries = make(map[string]bool)
	handler.tables = make(map[string]bool)
	handler.patterns = make([]sqlparser.Statement, 0)
	handler.logger = log.WithField("handler", "deny")
}

// Release releases all resources
func (handler *DenyHandler) Release() {
	handler.Reset()
}

// AddQueries normalizes and adds queries to the list that should be blacklisted
func (handler *DenyHandler) AddQueries(queries []string) error {
	for _, query := range queries {
		normalizedQuery, _, _, err := handler.parser.HandleRawSQLQuery(query)
		if err != nil {
			return err
		}
		handler.queries[normalizedQuery] = true
	}
	return nil
}

// RemoveQueries removes queries from the list that should be blacklisted
func (handler *DenyHandler) RemoveQueries(queries []string) error {
	for _, query := range queries {
		normalizedQuery, _, _, err := handler.parser.HandleRawSQLQuery(query)
		if err != nil {
			return err
		}
		delete(handler.queries, normalizedQuery)
	}
	return nil
}

// AddTables adds tables that should be blacklisted
func (handler *DenyHandler) AddTables(tableNames []string) {
	for _, tableName := range tableNames {
		handler.tables[tableName] = true
	}
}

// RemoveTables removes blacklisted tables
func (handler *DenyHandler) RemoveTables(tableNames []string) {
	for _, tableName := range tableNames {
		delete(handler.tables, tableName)
	}
}

// AddPatterns adds patterns that should be blacklisted
func (handler *DenyHandler) AddPatterns(patterns []string) error {
	parsedPatterns, err := common.ParsePatterns(patterns, handler.parser)
	if err != nil {
		return err
	}
	handler.patterns = parsedPatterns
	return nil
}
