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

// Package handlers contains all query handlers for AcraCensor:
// blacklist handler, which allows everything and forbids specific query/pattern/table;
// whitelist handler, which allows query/pattern/table and restricts/forbids everything else;
// ignore handler, which allows to ignore any query;
// and querycapture module that logs every unique query to the QueryCapture log.
//
// https://github.com/cossacklabs/acra/wiki/AcraCensor
package handlers

import (
	"bytes"
	"errors"
	log "github.com/sirupsen/logrus"
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
	// value without quotes
	ValueConfigPlaceholderRawReplacer = "VALUE_AE920B7D"
	// quoted value
	ValueConfigPlaceholderReplacer = "'" + ValueConfigPlaceholderRawReplacer + "'"

	ListOfValuesConfigPlaceholder            = "%%LIST_OF_VALUES%%"
	ListOfValuesConfigPlaceholderRawReplacer = "LIST_OF_VALUES_1KVA2TWY"
	ListOfValuesConfigPlaceholderReplacer    = "'" + ListOfValuesConfigPlaceholderRawReplacer + "'"

	SubqueryConfigPlaceholder         = "%%SUBQUERY%%"
	SubqueryConfigPlaceholderReplacer = "SELECT 'SUBQUERY_953IKLIJU4C8joVsZqCr8hYducQWNx'"
)

var SubqueryConfigPlaceholderReplacerParsed, _ = sqlparser.Parse(SubqueryConfigPlaceholderReplacer)

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
	sqlStripped, _ := sqlparser.SplitMarginComments(sql)

	// sometimes queries might have ; at the end, that should be stripped
	sqlStripped = strings.TrimSuffix(sqlStripped, ";")

	stmt, err := sqlparser.Parse(sqlStripped)
	if err != nil {
		return "", "", err
	}

	normalizedQ := sqlparser.String(stmt)

	// redact and mask VALUES
	sqlparser.Normalize(stmt, bv, ValuePlaceholder)
	redactedQ := sqlparser.String(stmt)

	return normalizedQ, redactedQ, nil
}

func checkPatternsMatching(patterns [][]sqlparser.SQLNode, query string) (bool, error) {
	statement, err := sqlparser.Parse(query)
	if err != nil {
		log.WithError(err).Errorln("Can't parse query")
		return false, ErrQuerySyntaxError
	}
	queryNodes, err := getAllNodes(statement)
	if err != nil {
		return false, err
	}
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
	matchOccurred = handleWherePatterns(queryNodes, patternNodes)
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
	querySelect, ok := queryNodes[0].(*sqlparser.Select)
	if !ok {
		return false
	}
	patternSelect, ok := patternNodes[0].(*sqlparser.Select)
	if !ok {
		return false
	}
	// check column count
	if len(querySelect.SelectExprs) != len(patternSelect.SelectExprs) {
		return false
	}
	// collect only SelectExpr, From, Where, OrderBy ... nodes without their children
	queryTopNodes, err := getTopNodes(querySelect)
	if err != nil {
		return false
	}
	patternTopNodes, err := getTopNodes(patternSelect)
	if err != nil {
		return false
	}

	// skip zero node - it's parent Select
	for i := 1; i < len(queryTopNodes); i++ {
		patternNode := patternTopNodes[i]
		queryNode := queryTopNodes[i]

		switch patternNode.(type) {
		case sqlparser.SelectExprs:
			for i, column := range patternSelect.SelectExprs {
				// if it pattern %%COLUMN%% node then we doesn't need to check query's node
				if isColumnPattern(column) {
					continue
				}
				// two nodes must be equal if pattern node is not %%COLUMN%%
				if !reflect.DeepEqual(column, querySelect.SelectExprs[i]) {
					return false
				}
			}
		case sqlparser.OrderBy:
			if queryOrderBy, ok := queryNode.(sqlparser.OrderBy); ok {
				if !matchOrderBy(patternNode.(sqlparser.OrderBy), queryOrderBy) {
					return false
				}
			}
		default:
			if !reflect.DeepEqual(patternNode, queryNode) {
				return false
			}
		}
	}
	return true
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

// handleWherePatterns try to match all WHERE conditions with supported patterns
func handleWherePatterns(queryNodes, patternNodes []sqlparser.SQLNode) bool {
	// collect only SelectExpr, From, Where, OrderBy ... nodes without their children
	queryTopNodes, err := getTopNodes(queryNodes[0])
	if err != nil {
		return false
	}
	patternTopNodes, err := getTopNodes(patternNodes[0])
	if err != nil {
		return false
	}
	hasStar := false
	if selectExpr, ok := patternNodes[0].(*sqlparser.Select); ok {
		hasStar = starFound(selectExpr.SelectExprs)
	}

	for i := 0; i < len(queryTopNodes); i++ {
		patternNode := patternTopNodes[i]
		queryNode := queryTopNodes[i]
		switch patternNode.(type) {
		case sqlparser.SelectExprs:
			if hasStar {
				// if select * in pattern then skip columns in query
				continue
			}
		case *sqlparser.Where:
			if _, ok := queryNode.(*sqlparser.Where); !ok {
				return false
			}
			if !handleWhereNode(patternNode.(*sqlparser.Where), queryNode.(*sqlparser.Where)) {
				return false
			}
			continue
		}

		if !reflect.DeepEqual(patternNode, queryNode) {
			return false
		}

	}
	return true
}

// isColumnPattern return true if this SelectExpr is our %%COLUMN%% pattern
func isColumnPattern(expr sqlparser.SelectExpr) bool {
	if aliased, ok := expr.(*sqlparser.AliasedExpr); ok {
		if colName, ok := aliased.Expr.(*sqlparser.ColName); ok {
			return strings.EqualFold(colName.Name.String(), ColumnConfigPlaceholderReplacer)
		}
		return false
	}
	return false
}

// isColumnReplacer returns true if node is %%COLUMN%%
func isColumnReplacer(node sqlparser.SQLNode, replacer string) bool {
	sqlColumn, ok := node.(*sqlparser.ColName)
	if !ok {
		return false
	}

	return strings.EqualFold(sqlColumn.Name.String(), replacer)
}

// isValueReplacer return true if node is SQLVal and has value same as replacer
func isValueReplacer(node sqlparser.SQLNode, replacer string) bool {
	sqlVal, ok := node.(*sqlparser.SQLVal)
	if !ok {
		return false
	}
	if sqlVal.Type != sqlparser.StrVal {
		return false
	}
	return bytes.Equal(sqlVal.Val, []byte(replacer))
}

// isValuePattern return true if node is ValueConfigPlaceholder pattern otherwise false
func isValuePattern(node sqlparser.SQLNode) bool {
	return isValueReplacer(node, ValueConfigPlaceholderRawReplacer)
}

// isListOfValuesPattern return true if node is ListOfValuesConfigPlaceholder pattern otherwise false
func isListOfValuesPattern(node sqlparser.SQLNode) bool {
	return isValueReplacer(node, ListOfValuesConfigPlaceholderRawReplacer)
}

// IsEqualComparisonNodes try to match patternNode with queryNode with supported patterns for ComparisonExpr
func IsEqualComparisonNodes(patternNode, queryNode *sqlparser.ComparisonExpr) bool {
	if reflect.DeepEqual(patternNode.Left, queryNode.Left) &&
		strings.EqualFold(patternNode.Operator, queryNode.Operator) &&
		reflect.DeepEqual(patternNode.Escape, queryNode.Escape) {

		switch patternNode.Operator {
		case sqlparser.InStr, sqlparser.NotInStr:
			switch patternNode.Right.(type) {
			case sqlparser.ValTuple:
				queryInNodes, ok := queryNode.Right.(sqlparser.ValTuple)
				if !ok {
					return false
				}
				patternInNodes := patternNode.Right.(sqlparser.ValTuple)

				// pattern may have less nodes due to %%list of values%% but not vice versa
				if len(queryInNodes) < len(patternInNodes) {
					return false
				}
				var i int
				for i = 0; i < len(patternInNodes); i++ {
					if isListOfValuesPattern(patternInNodes[i]) {
						// don't check least query nodes
						return true
					}
					if matchValuePattern(patternInNodes[i], queryInNodes[i]) {
						// we don't care about type of query value because pattern has %%VALUE%%
						continue
					}
					if matchSubqueryPattern(patternInNodes[i], queryInNodes[i]) {
						continue
					}
					if !reflect.DeepEqual(patternInNodes[i], queryInNodes[i]) {
						return false
					}
				}
				// if pattern has less nodes than query
				if i != len(queryInNodes) {
					return false
				}
				return true
			case *sqlparser.Subquery: // a in (select 1)
				patternSubquery := patternNode.Right.(*sqlparser.Subquery)

				querySubquery, ok := queryNode.Right.(*sqlparser.Subquery)
				if !ok {
					return false
				}
				if matchSubqueryPattern(patternSubquery, querySubquery) {
					return true
				}
				return reflect.DeepEqual(patternSubquery, querySubquery)
			}
		default:
			if isValuePattern(patternNode.Right) {
				return true
			}
			if matchSubqueryPattern(patternNode.Right, queryNode.Right) {
				return true
			}
		}
		// pattern node hasn't %%VALUE%% pattern so compare their values as is
		return reflect.DeepEqual(patternNode.Right, queryNode.Right)
	}
	return false
}

// matchValuePattern return true if pattern node is %%VALUE%% pattern and value of query node has type that masked with this pattern
func matchValuePattern(patternNode, queryNode sqlparser.SQLNode) bool {
	return isValuePattern(patternNode) && matchQueryNodeWithValuePattern(queryNode)
}

// matchSubqueryPattern return true if pattern are %%SUBQUERY%% and queryNode has correct type for this pattern otherwise false
func matchSubqueryPattern(patternNode, queryNode sqlparser.SQLNode) bool {
	if _, ok := patternNode.(*sqlparser.Subquery); !ok {
		return false
	}
	if _, ok := queryNode.(*sqlparser.Subquery); !ok {
		return false
	}
	// check that patterns query the same as our parsed placeholder
	if reflect.DeepEqual(patternNode.(*sqlparser.Subquery).Select, SubqueryConfigPlaceholderReplacerParsed) {
		return true
	}
	return false
}

// matchQueryNodeWithValuePattern return true if %%VALUE%% pattern should mask value of node
// return true for any literal values, boolean and null
// return false on other values like subqueries
func matchQueryNodeWithValuePattern(node sqlparser.SQLNode) bool {
	switch node.(type) {
	case *sqlparser.SQLVal, sqlparser.BoolVal, *sqlparser.NullVal:
		return true
	}
	return false
}

// matchRangeCondition handle range queries (age BETWEEN %%value%% and 5)
// return true if match (with or without %%value%% patterns) otherwise false
func matchRangeCondition(patternNode, queryNode *sqlparser.RangeCond) bool {
	if queryNode.Operator != patternNode.Operator {
		return false
	}
	if !reflect.DeepEqual(queryNode.Left, patternNode.Left) {
		return false
	}
	if !(matchValuePattern(patternNode.From, queryNode.From) || matchSubqueryPattern(patternNode.From, queryNode.From)) {
		if !reflect.DeepEqual(patternNode.From, queryNode.From) {
			return false
		}
	}
	if !(matchValuePattern(patternNode.To, queryNode.To) || matchSubqueryPattern(patternNode.To, queryNode.To)) {
		if !reflect.DeepEqual(patternNode.To, queryNode.To) {
			return false
		}
	}
	return true
}

// matchOrderBy handles order by construction
// return true if match otherwise false
func matchOrderBy(patternNode, queryNode sqlparser.OrderBy) bool {
	if len(patternNode) != len(queryNode) {
		return false
	}
	for index, _ := range patternNode {
		if !strings.EqualFold(patternNode[index].Direction, queryNode[index].Direction) {
			return false
		}
		if !isColumnReplacer(patternNode[index].Expr, ColumnConfigPlaceholderReplacer) {
			return false
		}
	}
	return true
}

// getAllNodes recusively walk through node and return all children of node with node itself
func getAllNodes(node sqlparser.SQLNode) ([]sqlparser.SQLNode, error) {
	var queryNodes []sqlparser.SQLNode
	err := sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
		queryNodes = append(queryNodes, node)
		return true, nil
	}, node)
	if err != nil {
		return nil, err
	}
	return queryNodes, nil
}

// getTopNodes walk only once at depth and return first level children of firstNode
func getTopNodes(firstNode sqlparser.SQLNode) ([]sqlparser.SQLNode, error) {
	goToSubtree := true
	var outNodes []sqlparser.SQLNode
	err := sqlparser.Walk(func(node sqlparser.SQLNode) (kontinue bool, err error) {
		if goToSubtree {
			goToSubtree = false
			return true, nil
		}
		outNodes = append(outNodes, node)
		return false, nil

	}, firstNode)
	return outNodes, err
}

// starFound return true if Select has '*' expression
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

// handleWhereNode process all patterns and rules related with Where conditions
func handleWhereNode(patternNode, queryNode sqlparser.SQLNode) bool {
	// get all fields of node struct without recursion
	patternWhereNodes, err := getTopNodes(patternNode)
	if err != nil {
		return false
	}
	queryWhereNodes, err := getTopNodes(queryNode)
	if err != nil {
		return false
	}

	// we don't need to check their length because some patterns may accept queries with different node count (list of  values as example)

	//if len(patternWhereNodes) != len(queryWhereNodes) {
	//	return false
	//}
	for i, patternWhereNode := range patternWhereNodes {
		queryWhereNode := queryWhereNodes[i]
		switch patternWhereNode.(type) {
		case *sqlparser.Where:
			if _, ok := queryWhereNode.(*sqlparser.Where); !ok {
				// different types
				return false
			}
			return handleWhereNode(patternWhereNode, queryWhereNode)
		case *sqlparser.AndExpr, *sqlparser.OrExpr, *sqlparser.NotExpr:
			// check that complex structs with children has same type and then recursively check them
			if reflect.TypeOf(queryWhereNode) != reflect.TypeOf(patternWhereNode) {
				return false
			}
			if !handleWhereNode(patternWhereNode, queryWhereNode) {
				return false
			}
			continue
		case *sqlparser.IsExpr:
			if queryIsExpr, ok := queryWhereNode.(*sqlparser.IsExpr); ok {
				if queryIsExpr.Operator != patternWhereNode.(*sqlparser.IsExpr).Operator {
					return false
				}
				if !handleWhereNode(patternWhereNode.(*sqlparser.IsExpr).Expr, queryWhereNode.(*sqlparser.IsExpr).Expr) {
					return false
				}
				continue
			}
			// query node has different type
			return false
		case *sqlparser.ComparisonExpr:
			if queryNodeComparison, ok := queryWhereNode.(*sqlparser.ComparisonExpr); ok && queryNodeComparison != nil {
				if IsEqualComparisonNodes(patternWhereNode.(*sqlparser.ComparisonExpr), queryNodeComparison) {
					continue
				}
			}
			return false
		case *sqlparser.RangeCond:
			if queryRangeCondition, ok := queryWhereNode.(*sqlparser.RangeCond); ok {
				if matchRangeCondition(patternWhereNode.(*sqlparser.RangeCond), queryRangeCondition) {
					continue
				}
			}
			return false
		case *sqlparser.ExistsExpr:
			if queryExists, ok := queryWhereNode.(*sqlparser.ExistsExpr); ok {
				if matchSubqueryPattern(patternWhereNode.(*sqlparser.ExistsExpr).Subquery, queryExists.Subquery) {
					continue
				}
				// break switch to reflect.DeepEqual whole node
				break
			}
			return false
		}
		// unknown and conditions without specific rules check recursively by values as is
		if !reflect.DeepEqual(patternWhereNode, queryWhereNode) {
			return false
		}
	}
	return true
}
