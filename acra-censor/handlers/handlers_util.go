package handlers

import (
	"errors"
	"github.com/xwb1989/sqlparser"
	"github.com/xwb1989/sqlparser/dependency/querypb"
	"reflect"
	"strings"
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
	ErrPatternCheckError               = errors.New("failed to check specified pattern match")
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
	// These constants are used to create unique SQL query that express security patterns (such patterns will be wittingly parsed correctly)
	SelectConfigPlaceholder              = "%%SELECT%%"
	SelectConfigPlaceholderReplacerPart1 = "SELECT"
	SelectConfigPlaceholderReplacerPart2 = "F1F0A98E"
	SelectConfigPlaceholderReplacer      = SelectConfigPlaceholderReplacerPart1 + " " + SelectConfigPlaceholderReplacerPart2
	ColumnConfigPlaceholder              = "%%COLUMN%%"
	ColumnConfigPlaceholderReplacer      = "COLUMN_A8D6EB40"
	WhereConfigPlaceholder               = "%%WHERE%%"
	WhereConfigPlaceholderReplacerPart1  = "WHERE"
	WhereConfigPlaceholderReplacerPart2  = "VALUE_EF930A9B = 'VALUE_CD329E0D'"
	WhereConfigPlaceholderReplacer       = WhereConfigPlaceholderReplacerPart1 + " " + WhereConfigPlaceholderReplacerPart2
	ValueConfigPlaceholder               = "%%VALUE%%"
	ValueConfigPlaceholderReplacer       = "'VALUE_AE920B7D'"
)

// TrimStringToN trims query to N chars.
func TrimStringToN(query string, n int) string {
	if len(query) <= n {
		return query
	}
	return query[:n]
}

// NormalizeAndRedactSQLQuery returns a normalized (lowercases SQL commands) SQL string,
// and redacted SQL string with the params stripped out for display.
// Taken from sqlparser package
func NormalizeAndRedactSQLQuery(sql string) (normalizedQuery string, redactedQuery string, error error) {
	bv := map[string]*querypb.BindVariable{}
	sqlStripped, comments := sqlparser.SplitMarginComments(sql)

	// sometimes queries might have ; at the end, that should be stripped
	sqlStripped = strings.TrimSuffix(sqlStripped, ";")

	stmt, err := sqlparser.Parse(sqlStripped)
	if err != nil {
		return "", "", err
	}

	normalizedQ := comments.Leading + sqlparser.String(stmt) + comments.Trailing

	// redact and mask VALUES
	sqlparser.Normalize(stmt, bv, ValuePlaceholder)
	redactedQ := comments.Leading + sqlparser.String(stmt) + comments.Trailing

	return normalizedQ, redactedQ, nil
}

func checkPatternsMatching(patterns [][]sqlparser.SQLNode, query string) (bool, error) {
	var queryNodes []sqlparser.SQLNode
	statement, err := sqlparser.Parse(query)
	if err != nil {
		return false, ErrQuerySyntaxError
	}
	sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
		queryNodes = append(queryNodes, node)
		return true, nil
	}, statement)
	for _, singlePatternNodes := range patterns {
		if checkSinglePatternMatch(queryNodes, singlePatternNodes) {
			return true, nil
		}
	}
	return false, nil
}

func checkSinglePatternMatch(queryNodes []sqlparser.SQLNode, patternNodes []sqlparser.SQLNode) bool {
	matchOccurred := false
	matchOccurred = handleSelectPattern(queryNodes, patternNodes)
	if matchOccurred {
		return true
	}
	matchOccurred = handleSelectColumnPattern(queryNodes, patternNodes)
	if matchOccurred {
		return true
	}
	matchOccurred = handleSelectWherePattern(queryNodes, patternNodes)
	if matchOccurred {
		return true
	}
	matchOccurred = handleValuePattern(queryNodes, patternNodes)
	if matchOccurred {
		return true
	}
	matchOccurred = handleStarPattern(queryNodes, patternNodes)
	if matchOccurred {
		return true
	}
	//query doesn't match any stored pattern
	return false
}

// handleSelectPattern handles %%SELECT%% pattern
func handleSelectPattern(queryNodes, patternNodes []sqlparser.SQLNode) bool {
	if reflect.TypeOf(queryNodes[0]) == reflect.TypeOf(patternNodes[0]) {
		if patternNodeSelect, ok := patternNodes[0].(*sqlparser.Select); ok && strings.EqualFold(sqlparser.String(patternNodeSelect.SelectExprs), SelectConfigPlaceholderReplacerPart2) {
			return true
		}
	}
	return false
}

// handleSelectColumnPattern handles SELECT %%COLUMN%% .. %%COLUMN%% pattern
func handleSelectColumnPattern(queryNodes, patternNodes []sqlparser.SQLNode) bool {
	matchDetected := false
	if len(patternNodes) != len(queryNodes) {
		return false
	}
	for index, patternNode := range patternNodes {
		if index == 0 || reflect.DeepEqual(patternNode, queryNodes[index]) {
			continue
		}
		if patternNodeColName, ok := patternNode.(*sqlparser.ColName); ok && patternNodeColName != nil {
			if queryNodeColName, ok := queryNodes[index].(*sqlparser.ColName); ok && queryNodeColName != nil {
				if strings.EqualFold(patternNodeColName.Name.String(), ColumnConfigPlaceholderReplacer) {
					matchDetected = true
				} else {
					return false
				}
			}
		}
	}
	return matchDetected
}

// handleSelectWherePattern handles SELECT a, b from t %%WHERE%% pattern
func handleSelectWherePattern(queryNodes, patternNodes []sqlparser.SQLNode) bool {
	patternWhereDetected := false
	queryWhereDetected := false
	for index, patternNode := range patternNodes {
		if index >= len(queryNodes) {
			return false
		}
		if index == 0 || reflect.DeepEqual(queryNodes[index], patternNode) {
			continue
		}
		if patternWhereNode, ok := patternNode.(*sqlparser.Where); ok && patternWhereNode != nil && strings.EqualFold(sqlparser.String(patternWhereNode.Expr), WhereConfigPlaceholderReplacerPart2) {
			patternWhereDetected = true
		}
		if queryWhereNode, ok := queryNodes[index].(*sqlparser.Where); ok && queryWhereNode != nil {
			queryWhereDetected = true
		}
		if queryWhereDetected && patternWhereDetected {
			return true
		}
		return false
	}
	//this is a case when pattern == query
	return true
}

// handle SELECT a, b FROM t1 WHERE userID=%%VALUE%% pattern
func handleValuePattern(queryNodes, patternNodes []sqlparser.SQLNode) bool {
	patternNodeOffset := 0
	queryNodeOffset := 0

	matchDetected := false
	for index := 1; index < len(patternNodes); index++ {
		//This means that checked query nodes are equal to pattern and no more nodes remained, so query matches pattern (no matter if pattern has remained nodes)
		if index+queryNodeOffset >= len(queryNodes) {
			break
		}
		//This means that checked query nodes are equal to pattern but some more nodes remained, so query doesn't match pattern
		if index+patternNodeOffset >= len(patternNodes) {
			return false
		}
		//Start check matching
		if reflect.DeepEqual(patternNodes[index+patternNodeOffset], queryNodes[index+queryNodeOffset]) {
			continue
		}
		//handle '*' case
		if patternSelectExprs, ok := patternNodes[index+patternNodeOffset].(sqlparser.SelectExprs); ok {
			if _, ok := queryNodes[index+queryNodeOffset].(sqlparser.SelectExprs); ok {
				if starFound(patternSelectExprs) {
					for i := index; i < len(queryNodes); i++ {
						if _, ok := queryNodes[i].(sqlparser.TableExprs); ok {
							break
						}
						queryNodeOffset++
					}
					for i := index; i < len(patternNodes); i++ {
						if _, ok := patternNodes[i].(sqlparser.TableExprs); ok {
							break
						}
						patternNodeOffset++
					}
					continue
				}
			}
		}
		if patternNodeComparison, ok := patternNodes[index+patternNodeOffset].(*sqlparser.ComparisonExpr); ok && patternNodeComparison != nil {
			if queryNodeComparison, ok := queryNodes[index+queryNodeOffset].(*sqlparser.ComparisonExpr); ok && queryNodeComparison != nil {
				if IsEqualComparisonNode(patternNodeComparison, queryNodeComparison) {
					matchDetected = true
				}
			}
		}
	}
	return matchDetected
}

func IsEqualComparisonNode(patternNode, queryNode *sqlparser.ComparisonExpr) bool {
	if reflect.DeepEqual(patternNode.Left, queryNode.Left) &&
		strings.EqualFold(patternNode.Operator, queryNode.Operator) &&
		reflect.DeepEqual(patternNode.Escape, queryNode.Escape) {
		if strings.EqualFold(sqlparser.String(patternNode.Right), ValueConfigPlaceholderReplacer) {
			return true
		}
	}
	return false
}

// handleStarPattern handles SELECT * FROM table %%WHERE%% pattern
func handleStarPattern(queryNodes, patternNodes []sqlparser.SQLNode) bool {
	patternWhereDetected := false
	queryWhereDetected := false
	patternNodeOffset := 0
	queryNodeOffset := 0
	for index := 1; index < len(patternNodes); index++ {
		if index+patternNodeOffset >= len(patternNodes) || index+queryNodeOffset >= len(queryNodes) {
			return false
		}
		if reflect.DeepEqual(patternNodes[index+patternNodeOffset], queryNodes[index+queryNodeOffset]) {
			continue
		}
		if patternSelectExpr, ok := patternNodes[index+patternNodeOffset].(sqlparser.SelectExprs); ok && starFound(patternSelectExpr) {
			if _, ok := queryNodes[index+queryNodeOffset].(sqlparser.SelectExprs); ok {
				for i := index; i < len(queryNodes); i++ {
					if _, ok := queryNodes[i].(sqlparser.TableExprs); ok {
						break
					}
					queryNodeOffset++
				}
				for i := index; i < len(queryNodes); i++ {
					if _, ok := patternNodes[i].(sqlparser.TableExprs); ok {
						break
					}
					patternNodeOffset++
				}
				continue
			}
		}
		if patternWhereNode, ok := patternNodes[index+patternNodeOffset].(*sqlparser.Where); ok && patternWhereNode != nil && strings.EqualFold(sqlparser.String(patternWhereNode.Expr), WhereConfigPlaceholderReplacerPart2) {
			patternWhereDetected = true
		}
		if queryWhereNode, ok := queryNodes[index+queryNodeOffset].(*sqlparser.Where); ok && queryWhereNode != nil {
			queryWhereDetected = true
		}
		if queryWhereDetected && patternWhereDetected {
			return true
		}
		return false
	}
	//this is a case when pattern == query
	return true
}
func starFound(selectExpression sqlparser.SelectExprs) bool {
	starDetected := false
	sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
		if _, ok := node.(*sqlparser.StarExpr); ok {
			starDetected = true
			return false, nil
		}
		return true, nil
	}, selectExpression)
	return starDetected
}
