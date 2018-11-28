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
func (handler *BlacklistHandler) CheckQuery(normalizedQuery string, parsedQuery sqlparser.Statement) (bool, error) {
	//Check exact queries
	if len(handler.queries) != 0 {
		queryMatch := common.CheckExactQueriesMatch(normalizedQuery, handler.queries)
		if queryMatch {
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(common.ErrQueryInBlacklist).Errorln("Query has been blocked by blacklist [queries]")
			return false, common.ErrQueryInBlacklist
		}
	}
	//Check tables
	if len(handler.tables) != 0 {
		atLeastOneTableInBlacklist, _ := common.CheckTableNamesMatch(parsedQuery, handler.tables)
		if atLeastOneTableInBlacklist {
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(common.ErrQueryInBlacklist).Errorln("Query has been blocked by blacklist [tables]")
			return false, common.ErrAccessToForbiddenTableBlacklist
		}
	}
	//Check patterns
	if len(handler.patterns) != 0 {
		matchingOccurred := common.CheckPatternsMatching(handler.patterns, parsedQuery)
		if matchingOccurred {
			return false, common.ErrBlacklistPatternMatch
		}
	}

	//Our blacklist is empty, so let's continue further verification
	return true, nil
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
func (handler *BlacklistHandler) AddQueries(queries []string) error {
	for _, query := range queries {
		normalizedQuery, _, _, err := common.HandleRawSQLQuery(query)
		if err != nil {
			return err
		}
		handler.queries[normalizedQuery] = true
	}
	return nil
}

// RemoveQueries removes queries from the list that should be blacklisted
func (handler *BlacklistHandler) RemoveQueries(queries []string) error {
	for _, query := range queries {
		normalizedQuery, _, _, err := common.HandleRawSQLQuery(query)
		if err != nil {
			return err
		}
		delete(handler.queries, normalizedQuery)
	}
	return nil
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
