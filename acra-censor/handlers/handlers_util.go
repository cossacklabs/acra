package handlers

import (
	"errors"
	"strings"
)

var ErrQueryNotInWhitelist = errors.New("query not in whitelist")
var ErrQueryInBlacklist = errors.New("query in blacklist")

var ErrAccessToForbiddenTableBlacklist = errors.New("query tries to access forbidden table")
var ErrAccessToForbiddenTableWhitelist = errors.New("query tries to access forbidden table")

var ErrForbiddenSqlStructureBlacklist = errors.New("query's structure is forbidden")
var ErrForbiddenSqlStructureWhitelist = errors.New("query's structure is forbidden")

var ErrParseTablesBlacklist = errors.New("parsing tables error")
var ErrParseSqlRuleBlacklist = errors.New("parsing security rules error")

var ErrParseTablesWhitelist = errors.New("parsing tables error")
var ErrParseSqlRuleWhitelist = errors.New("parsing security rules error")

var ErrNotImplemented = errors.New("not implemented yet")

var ErrQuerySyntaxError = errors.New("fail to parse specified query")
var ErrStructureSyntaxError = errors.New("fail to parse specified structure")

var ErrComplexSerializationError = errors.New("can't perform complex serialization of queries")
var ErrSingleQueryCaptureError = errors.New("can't capture single query")
var ErrUnexpectedCaptureChannelClose = errors.New("unexpected channel closing while query logging")

var ErrUnexpectedTypeError = errors.New("should never appear")

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
