package handlers

import (
	"errors"
	"strings"
)

// Errors returned during parsing SQL queries.
var (
	ErrQueryNotInWhitelist             = errors.New("query not in whitelist")
	ErrQueryInBlacklist                = errors.New("query in blacklist")
	ErrAccessToForbiddenTableBlacklist = errors.New("query tries to access forbidden table")
	ErrAccessToForbiddenTableWhitelist = errors.New("query tries to access forbidden table")
	ErrForbiddenSqlStructureBlacklist  = errors.New("query's structure is forbidden")
	ErrForbiddenSqlStructureWhitelist  = errors.New("query's structure is forbidden")
	ErrParseSqlRuleBlacklist           = errors.New("parsing security rules error")
	ErrParseSqlRuleWhitelist           = errors.New("parsing security rules error")
	ErrNotImplemented                  = errors.New("not implemented yet")
	ErrQuerySyntaxError                = errors.New("fail to parse specified query")
	ErrComplexSerializationError       = errors.New("can't perform complex serialization of queries")
	ErrSingleQueryCaptureError         = errors.New("can't capture single query")
	ErrCantOpenFileError               = errors.New("can't open file to write queries")
	ErrCantReadQueriesFromFileError    = errors.New("can't read queries from file")
	ErrUnexpectedCaptureChannelClose   = errors.New("unexpected channel closing while query logging")
	ErrUnexpectedTypeError             = errors.New("should never appear")
)

const (
	// Maximum query length for logging to syslog.
	LogQueryLength = 100
)

func removeDuplicates(input []string) []string {
	keys := make(map[string]bool)
	var result []string
	for _, entry := range input {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			result = append(result, entry)
		}
	}
	return result
}

func contains(queries []string, query string) (bool, int) {
	for index, queryFromRange := range queries {
		if strings.EqualFold(strings.ToLower(queryFromRange), strings.ToLower(query)) {
			return true, index
		}
	}
	return false, 0
}

// Trims query to N chars.
func TrimStringToN(query string, n int) string {
	if len(query) <= n {
		return query
	}
	return query[:n]
}
