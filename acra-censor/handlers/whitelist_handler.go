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
func (handler *WhitelistHandler) CheckQuery(normalizedQuery string, parsedQuery sqlparser.Statement) (bool, error) {
	//Check exact queries
	if len(handler.queries) != 0 {
		queryMatch := common.CheckExactQueriesMatch(normalizedQuery, handler.queries)
		if !queryMatch {
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(common.ErrQueryNotInWhitelist).Errorln("Query has been blocked by whitelist [queries]")
			return false, common.ErrQueryNotInWhitelist
		}
	}
	//Check tables
	if len(handler.tables) != 0 {
		_, allTablesInWhitelist := common.CheckTableNamesMatch(parsedQuery, handler.tables)
		if !allTablesInWhitelist {
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(common.ErrQueryNotInWhitelist).Errorln("Query has been blocked by whitelist [tables]")
			return false, common.ErrAccessToForbiddenTableWhitelist
		}
	}
	//Check patterns
	if len(handler.patterns) != 0 {
		matchingOccurred := common.CheckPatternsMatching(handler.patterns, parsedQuery)
		if !matchingOccurred {
			return false, common.ErrWhitelistPatternMismatch
		}
	}

	//Our whitelist is empty, so let's continue further verification
	return true, nil
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
func (handler *WhitelistHandler) AddQueries(queries []string) error {
	for _, query := range queries {
		normalizedQuery, _, _, err := common.HandleRawSQLQuery(query)
		if err != nil {
			return err
		}
		handler.queries[normalizedQuery] = true
	}
	return nil
}

// RemoveQueries removes queries from the list that should be whitelisted
func (handler *WhitelistHandler) RemoveQueries(queries []string) error {
	for _, query := range queries {
		normalizedQuery, _, _, err := common.HandleRawSQLQuery(query)
		if err != nil {
			return err
		}
		delete(handler.queries, normalizedQuery)
	}
	return nil
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
	parsedPatterns, err := common.ParsePatterns(patterns)
	if err != nil {
		return err
	}
	handler.patterns = parsedPatterns
	return nil
}
