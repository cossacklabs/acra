package handlers

import (
	"errors"
	"strings"
)

var ErrQueryNotInWhitelist = errors.New("acra-censor: query not in whitelist")
var ErrQueryInBlacklist = errors.New("acra-censor: query in blacklist")

var ErrAccessToForbiddenTableBlacklist = errors.New("acra-censor: query tries to access forbidden table")
var ErrAccessToForbiddenTableWhitelist = errors.New("acra-censor: query tries to access forbidden table")

var ErrForbiddenSqlStructureBlacklist = errors.New("acra-censor: query's structure is forbidden")
var ErrForbiddenSqlStructureWhitelist = errors.New("acra-censor: query's structure is forbidden")

var ErrParseSqlRuleBlacklist = errors.New("acra-censor: parsing security rules error")

var ErrParseSqlRuleWhitelist = errors.New("acra-censor: parsing security rules error")

var ErrNotImplemented = errors.New("acra-censor: not implemented yet")

var ErrQuerySyntaxError = errors.New("acra-censor: fail to parse specified query")

var ErrComplexSerializationError = errors.New("acra-censor: can't perform complex serialization of queries")
var ErrSingleQueryCaptureError = errors.New("acra-censor: can't capture single query")
var ErrCantOpenFileError = errors.New("acra-censor: can't open file to write queries")
var ErrCantReadQueriesFromFileError = errors.New("acra-censor: can't read queries from file")
var ErrUnexpectedCaptureChannelClose = errors.New("acra-censor: unexpected channel closing while query logging")

var ErrUnexpectedTypeError = errors.New("acra-censor: should never appear")

const (
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
func TrimStringToN(query string, n int) string {
	if len(query) <= n {
		return query
	}
	return query[:n]
}
