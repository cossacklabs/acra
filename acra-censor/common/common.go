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

package common

import (
	"errors"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/sqlparser/dependency/querypb"
	log "github.com/sirupsen/logrus"
	"strings"
)

type pattern struct {
	placeholder string
	replacer    string
}

// Errors returned by censor
var (
	ErrDenyByQueryError                = errors.New("deny by query")
	ErrDenyByTableError                = errors.New("deny by table")
	ErrDenyByPatternError              = errors.New("deny by pattern")
	ErrPatternSyntaxError              = errors.New("fail to parse specified pattern")
	ErrPatternCheckError               = errors.New("failed to check specified pattern match")
	ErrQuerySyntaxError                = errors.New("fail to parse specified query")
	ErrCantReadQueriesFromStorageError = errors.New("can't read queries from storage")
	ErrUnexpectedTypeError             = errors.New("should never appear")
	ErrDenyAllError                    = errors.New("deny all queries error")
	ErrCensorConfigurationError        = errors.New("configuration error")
)

const (
	// LogQueryLength is maximum query length for logging to syslog.
	LogQueryLength = 100
	// ValueMask is used to mask real Values from SQL queries before logging to syslog.
	ValueMask = "replaced"
)

const (
	// UnionPlaceholder is used when matching %%UNION%% pattern
	UnionPlaceholder = "%%UNION%%"
	// UnionReplacer is used when matching %%UNION%% pattern
	UnionReplacer = "SELECT 254775710223443243272234290 UNION SELECT 486264166657867240626457666"
	// SelectPlaceholder is used when matching %%SELECT%% pattern
	SelectPlaceholder = "%%SELECT%%"
	// SelectReplacer is used when matching %%SELECT%% pattern
	SelectReplacer = "SELECT 253768160274445518137315681"
	// InsertPlaceholder is used when matching %%INSERT%% pattern
	InsertPlaceholder = "%%INSERT%%"
	// InsertReplacer is used when matching %%INSERT%% pattern
	InsertReplacer = "INSERT INTO table_150624360841713829746677497 (column_454716724) VALUES (value_151516596)"
	// UpdatePlaceholder is used when matching %%UPDATE%% pattern
	UpdatePlaceholder = "%%UPDATE%%"
	// UpdateReplacer is used when matching %%UPDATE%% pattern
	UpdateReplacer = "UPDATE table_795749362101944825892661393 SET column_148943040 = 577742781 WHERE row_788570922 = 840343494"
	// DeletePlaceholder is used when matching %%DELETE%% pattern
	DeletePlaceholder = "%%DELETE%%"
	// DeleteReplacer is used when matching %%DELETE%% pattern
	DeleteReplacer = "DELETE FROM table_359557854899217835429634591"
	// BeginPlaceholder is used when matching BEGIN pattern
	BeginPlaceholder = "%%BEGIN%%"
	// BeginReplacer is used when matching BEGIN pattern
	BeginReplacer = "BEGIN"
	// CommitPlaceholder is used when matching COMMIT pattern
	CommitPlaceholder = "%%COMMIT%%"
	// CommitReplacer is used when matching COMMIT pattern
	CommitReplacer = "COMMIT"
	// RollbackPlaceholder is used when matching ROLLBACK pattern
	RollbackPlaceholder = "%%ROLLBACK%%"
	// RollbackReplacer is used when matching ROLLBACK pattern
	RollbackReplacer = "ROLLBACK"

	// WherePlaceholder is used when matching %%WHERE%% pattern
	WherePlaceholder = "%%WHERE%%"
	// WhereReplacer is used when matching %%WHERE%% pattern
	WhereReplacer = "where value = where_651453831047102383248696721"
	// ValuePlaceholder is used when matching %%VALUE%% pattern
	ValuePlaceholder = "%%VALUE%%"
	// ValueReplacer is used when matching %%VALUE%% pattern
	ValueReplacer = "'value_877452131373673274532373116'"
	// SubqueryPlaceholder is used when matching %%SUBQUERY%% pattern
	SubqueryPlaceholder = "%%SUBQUERY%%"
	// SubqueryReplacer is used when matching %%SUBQUERY%% pattern
	SubqueryReplacer = "SELECT 'subquery_820753242875385807714016705'"
	// ListOfValuesPlaceholder is used when matching %%LIST_OF_VALUES%% pattern
	ListOfValuesPlaceholder = "%%LIST_OF_VALUES%%"
	// ListOfValuesReplacer is used when matching %%LIST_OF_VALUES%% pattern
	ListOfValuesReplacer = "'list_of_values_980254824737236160411017007'"
	// ColumnPlaceholder is used when matching %%COLUMN%% pattern
	ColumnPlaceholder = "%%COLUMN%%"
	// ColumnReplacer is used when matching %%COLUMN%% pattern
	ColumnReplacer = "column_443112402399486586659464580"
)

// UnionPatternStatement is used while comparison with %%UNION%% pattern
var UnionPatternStatement, _ = sqlparser.Parse(UnionReplacer)

// SelectPatternStatement is used while comparison with %%SELECT%% pattern
var SelectPatternStatement, _ = sqlparser.Parse(SelectReplacer)

// InsertPatternStatement is used while comparison with %%INSERT%% pattern
var InsertPatternStatement, _ = sqlparser.Parse(InsertReplacer)

// UpdatePatternStatement is used while comparison with %%UPDATE%% pattern
var UpdatePatternStatement, _ = sqlparser.Parse(UpdateReplacer)

// DeletePatternStatement is used while comparison with %%DELETE%% pattern
var DeletePatternStatement, _ = sqlparser.Parse(DeleteReplacer)

// ValuePatternStatement is used while comparison with %%VALUE%% pattern
// replacer is used without quotes
var ValuePatternStatement = sqlparser.NewStrVal([]byte(ValueReplacer[1:34]))

// SubqueryPatternStatement is used while comparison with %%SUBQUERY%% pattern
var SubqueryPatternStatement, _ = sqlparser.Parse(SubqueryReplacer)

// ListOfValuePatternStatement is used while comparison with %%LIST_OF_VALUES%% pattern
// replacer is used without quotes
var ListOfValuePatternStatement = sqlparser.NewStrVal([]byte(ListOfValuesReplacer[1:43]))

// ColumnPatternStatement is used while comparison with %%COLUMN%% pattern
var ColumnPatternStatement = sqlparser.NewColIdent(ColumnReplacer)

// WherePatternStatement is used while comparison with %%WHERE%% pattern
var WherePatternStatement, _ = sqlparser.Parse("SELECT * FROM table_883909268 " + WhereReplacer)

var patterns = []pattern{
	{SelectPlaceholder, SelectReplacer},
	{UnionPlaceholder, UnionReplacer},
	{InsertPlaceholder, InsertReplacer},
	{UpdatePlaceholder, UpdateReplacer},
	{DeletePlaceholder, DeleteReplacer},
	{BeginPlaceholder, BeginReplacer},
	{CommitPlaceholder, CommitReplacer},
	{RollbackPlaceholder, RollbackReplacer},
	{WherePlaceholder, WhereReplacer},
	{ValuePlaceholder, ValueReplacer},
	{SubqueryPlaceholder, SubqueryReplacer},
	{ListOfValuesPlaceholder, ListOfValuesReplacer},
	{ColumnPlaceholder, ColumnReplacer},
}

// ParsePatterns replace placeholders with our values which used to match patterns and parse them with sqlparser
func ParsePatterns(rawPatterns []string) ([]sqlparser.Statement, error) {
	patternValue := ""
	var outputPatterns []sqlparser.Statement
	for _, pattern := range rawPatterns {
		patternValue = pattern
		for _, pattern := range patterns {
			patternValue = strings.Replace(patternValue, pattern.placeholder, pattern.replacer, -1)
		}
		statement, err := sqlparser.Parse(patternValue)
		if err != nil {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).WithField("pattern", patternValue).WithError(err).Errorln("Can't parse specified pattern")
			return nil, ErrPatternSyntaxError
		}
		outputPatterns = append(outputPatterns, statement)
	}
	return outputPatterns, nil
}

// TrimStringToN trims query to N chars.
func TrimStringToN(query string, n int) string {
	if len(query) <= n {
		return query
	}
	return query[:n]
}

// HandleRawSQLQuery returns a normalized (lowercases SQL commands) SQL string,
// and redacted SQL string with the params stripped out for display.
// Taken from sqlparser package
func HandleRawSQLQuery(sql string) (normalizedQuery, redactedQuery string, parsedQuery sqlparser.Statement, err error) {
	bv := map[string]*querypb.BindVariable{}
	sqlStripped, _ := sqlparser.SplitMarginComments(sql)

	// sometimes queries might have ; at the end, that should be stripped
	sqlStripped = strings.TrimSuffix(sqlStripped, ";")

	stmt, err := sqlparser.Parse(sqlStripped)
	if err != nil {
		log.WithError(err).Errorln("Can't process raw query")
		return "", "", nil, ErrQuerySyntaxError
	}
	outputStmt, _ := sqlparser.Parse(sqlStripped)

	normalizedQ := sqlparser.String(stmt)

	// redact and mask VALUES
	sqlparser.Normalize(stmt, bv, ValueMask)
	redactedQ := sqlparser.String(stmt)

	return normalizedQ, redactedQ, outputStmt, nil
}

// CheckPatternsMatching evaluates if parsed query matches specified set of patterns
func CheckPatternsMatching(patterns []sqlparser.Statement, parsedQuery sqlparser.Statement) bool {
	for _, pattern := range patterns {
		if checkSinglePatternMatch(parsedQuery, pattern) {
			return true
		}
	}
	return false
}

// CheckExactQueriesMatch evaluates if query presents in set of queries
func CheckExactQueriesMatch(normalizedQuery string, setOfQueries map[string]bool) bool {
	if !setOfQueries[normalizedQuery] {
		return false
	}
	return true
}

// CheckTableNamesMatch evaluates if query contains table presented in specified set of tables
func CheckTableNamesMatch(parsedQuery sqlparser.Statement, setOfTables map[string]bool) (bool, bool) {
	atLeastOneTableNameMatch := false
	allTableNamesMatch := false

	switch query := parsedQuery.(type) {
	case *sqlparser.Select:
		atLeastOneTableNameMatch, allTableNamesMatch = checkTableExprsMatch(query.From, setOfTables)
		break
	case *sqlparser.Insert:
		if setOfTables[query.Table.Name.String()] {
			atLeastOneTableNameMatch = true
			allTableNamesMatch = true
		} else {
			atLeastOneTableNameMatch = false
			allTableNamesMatch = false
		}
		break
	default:
		//TODO other query types
		return false, false
	}

	return atLeastOneTableNameMatch, allTableNamesMatch
}

// Tables matchers
func checkTableExprsMatch(tables sqlparser.TableExprs, setOfTables map[string]bool) (bool, bool) {
	oneTableMatch := false
	allTablesMatch := false
	counter := 0
	for _, tableExpr := range tables {
		oneTableMatchInternal, allTablesMatchInternal := checkTableExprMatch(tableExpr, setOfTables)
		if oneTableMatchInternal {
			oneTableMatch = true
			if allTablesMatchInternal {
				counter++
			} else {
				break
			}
		}
	}
	if counter == len(tables) {
		allTablesMatch = true
	}
	return oneTableMatch, allTablesMatch
}

func checkTableExprMatch(table sqlparser.TableExpr, setOfTables map[string]bool) (bool, bool) {
	oneTableMatch := false
	allTablesMatch := false

	switch tbl := table.(type) {
	case *sqlparser.AliasedTableExpr:
		if setOfTables[sqlparser.String(tbl.Expr)] {
			oneTableMatch = true
			allTablesMatch = true
		}
	case *sqlparser.JoinTableExpr:
		oneLeftTableMatchInternal, allLeftTablesMatchInternal := checkTableExprMatch(tbl.LeftExpr, setOfTables)
		oneRightTableMatchInternal, allRightTablesMatchInternal := checkTableExprMatch(tbl.RightExpr, setOfTables)
		if oneLeftTableMatchInternal || oneRightTableMatchInternal {
			oneTableMatch = true
		}
		if allLeftTablesMatchInternal && allRightTablesMatchInternal {
			allTablesMatch = true
		}

	case *sqlparser.ParenTableExpr:
		oneTableMatch, allTablesMatch = checkTableExprsMatch(tbl.Exprs, setOfTables)
	}
	return oneTableMatch, allTablesMatch
}
