package handlers

import (
	"errors"
	"github.com/xwb1989/sqlparser"
	"github.com/xwb1989/sqlparser/dependency/querypb"
	"strings"
)

var ErrQueryNotInWhitelist = errors.New("query not in whitelist")
var ErrQueryInBlacklist = errors.New("query in blacklist")
var ErrAccessToForbiddenTableBlacklist = errors.New("query tries to access forbidden table")
var ErrAccessToForbiddenTableWhitelist = errors.New("query tries to access forbidden table")
var ErrForbiddenSqlStructureBlacklist = errors.New("query's structure is forbidden")
var ErrForbiddenSqlStructureWhitelist = errors.New("query's structure is forbidden")
var ErrParseSqlRuleBlacklist = errors.New("parsing security rules error")
var ErrParseSqlRuleWhitelist = errors.New("parsing security rules error")
var ErrNotImplemented = errors.New("not implemented yet")
var ErrQuerySyntaxError = errors.New("fail to parse specified query")
var ErrComplexSerializationError = errors.New("can't perform complex serialization of queries")
var ErrSingleQueryCaptureError = errors.New("can't capture single query")
var ErrCantOpenFileError = errors.New("can't open file to write queries")
var ErrCantReadQueriesFromFileError = errors.New("can't read queries from file")
var ErrUnexpectedCaptureChannelClose = errors.New("unexpected channel closing while query logging")
var ErrUnexpectedTypeError = errors.New("should never appear")

const LogQueryLength = 100

const ValuePlaceholder = "replaced"

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

// TrimStringToN trims query to N chars.
func TrimStringToN(query string, n int) string {
	if len(query) <= n {
		return query
	}
	return query[:n]
}

// RedactSQLQuery returns a sql string with the params stripped out for display. Taken from sqlparser package
func RedactSQLQuery(sql string) (string, error) {
	bv := map[string]*querypb.BindVariable{}
	sqlStripped, comments := sqlparser.SplitMarginComments(sql)

	stmt, err := sqlparser.Parse(sqlStripped)
	if err != nil {
		return "", err
	}
	sqlparser.Normalize(stmt, bv, ValuePlaceholder)
	return comments.Leading + sqlparser.String(stmt) + comments.Trailing, nil
}
