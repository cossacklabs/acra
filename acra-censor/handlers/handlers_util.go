package handlers

import (
	"errors"
	"github.com/xwb1989/sqlparser"
	"github.com/xwb1989/sqlparser/dependency/querypb"
)

// Errors returned during parsing SQL queries.
var (
	ErrQueryNotInWhitelist             = errors.New("query not in whitelist")
	ErrQueryInBlacklist                = errors.New("query in blacklist")
	ErrAccessToForbiddenTableBlacklist = errors.New("query tries to access forbidden table")
	ErrAccessToForbiddenTableWhitelist = errors.New("query tries to access forbidden table")
	ErrBlacklistPatternMatch           = errors.New("query's structure is forbidden")
	ErrWhitelistPatternMismatch        = errors.New("query's structure is forbidden")
	ErrNotImplemented                  = errors.New("not implemented yet")
	ErrPatternSyntaxError              = errors.New("fail to parse specified pattern")
	ErrQuerySyntaxError                = errors.New("fail to parse specified query")
	ErrComplexSerializationError       = errors.New("can't perform complex serialization of queries")
	ErrSingleQueryCaptureError         = errors.New("can't capture single query")
	ErrCantOpenFileError               = errors.New("can't open file to write queries")
	ErrCantReadQueriesFromFileError    = errors.New("can't read queries from file")
	ErrUnexpectedCaptureChannelClose   = errors.New("unexpected channel closing while query logging")
	ErrUnexpectedTypeError             = errors.New("should never appear")
)

const (
	// LogQueryLength is maximum query length for logging to syslog.
	LogQueryLength = 100
	// ValuePlaceholder used to mask real Values from SQL queries before logging to syslog.
	ValuePlaceholder = "replaced"
	// SelectConfigPlaceholder expresses pattern that matches to all "select" SQL queries (can be used in censor' configuration file)
	SelectConfigPlaceholder = "%%SELECT%%"
	// constants used to create unique SQL query (SelectConfigPlaceholderReplacer will be wittingly parsed correctly)
	SelectConfigPlaceholderReplacerPart1 = "SELECT"
	SelectConfigPlaceholderReplacerPart2 = "F1F0A98E"
	SelectConfigPlaceholderReplacer      = SelectConfigPlaceholderReplacerPart1 + " " + SelectConfigPlaceholderReplacerPart2
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
