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
	ValueConfigPlaceholderReplacer       = "'VALUE_AE920B7D'"
)

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

func checkPatternsMatching(patterns [][]sqlparser.SQLNode, query string) (bool, error) {
	var queryNodes []sqlparser.SQLNode
	statement, err := sqlparser.Parse(query)
	if err != nil {
		log.WithError(err).Errorln("Can't parse query")
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

	for i := 0; i < len(queryTopNodes); i++ {
		patternNode := patternTopNodes[i]
		queryNode := queryTopNodes[i]
		if _, ok := queryNode.(sqlparser.SelectExprs); ok {
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
			// check other nodes on equal (except SelectExprs)
		} else if !reflect.DeepEqual(patternNode, queryNode) {
			return false
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

// handle SELECT a, b FROM t1 WHERE userID=%%VALUE%% pattern
func handleValuePattern(queryNodes, patternNodes []sqlparser.SQLNode) bool {
	querySelect, ok := queryNodes[0].(*sqlparser.Select)
	if !ok {
		return false
	}
	patternSelect, ok := patternNodes[0].(*sqlparser.Select)
	if !ok {
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
	hasStar := starFound(patternSelect.SelectExprs)
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
			patternWhereNodes, err := getTopNodes(patternNode)
			if err != nil {
				return false
			}
			queryWhereNodes, err := getTopNodes(queryNode)
			if err != nil {
				return false
			}
			if len(patternWhereNodes) != len(queryWhereNodes) {
				return false
			}
			for i, patternWhereNode := range patternWhereNodes {
				queryWhereNode := queryWhereNodes[i]
				if patternNodeComparison, ok := patternWhereNode.(*sqlparser.ComparisonExpr); ok && patternNodeComparison != nil {
					if queryNodeComparison, ok := queryWhereNode.(*sqlparser.ComparisonExpr); ok && queryNodeComparison != nil {
						if IsEqualComparisonNode(patternNodeComparison, queryNodeComparison) {
							continue
						}
					}
				}
				if !reflect.DeepEqual(patternWhereNode, queryWhereNode) {
					return false
				}
			}
			continue
		}

		if !reflect.DeepEqual(patternNode, queryNode) {
			return false
		}

	}
	return true
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
