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
	"fmt"
	"github.com/xwb1989/sqlparser"
	"testing"
)

// TestHandleRangeCondition test queries with "column BETWEEN VALUE1 and VALUE2"
func TestHandleRangeCondition(t *testing.T) {
	patterns := []string{
		// left side value placeholder
		fmt.Sprintf("select 1 from t where param between %s and 2", ValueConfigPlaceholder),
		// right side value placeholder
		fmt.Sprintf("select 1 from t where param between 1 and %s", ValueConfigPlaceholder),
		// two sides placeholder
		fmt.Sprintf("select 1 from t where param between %s and %s", ValueConfigPlaceholder, ValueConfigPlaceholder),
		// two explicit int values
		"select 1 from t where param between 1 and 2",
		// two explicit str values
		"select 1 from t where param between 'qwe' and 'asd'",
		// subqueries instead values
		"select 1 from t where param between (select 1) and (select 2)",
		// subqueries with %%SUBQUERY%% placeholder
		fmt.Sprintf("select 1 from t where param between (%s) and (%s)", SubqueryConfigPlaceholder, SubqueryConfigPlaceholder),
		// subqueries with %%SUBQUERY%% and %%VALUE%% placeholders
		fmt.Sprintf("select 1 from t where param between (%s) and %s", SubqueryConfigPlaceholder, ValueConfigPlaceholder),
	}
	parsedPatterns, err := ParsePatterns(patterns)
	if err != nil {
		t.Fatal(err)
	}
	notMatchableQueries := [][]string{
		// left side value placeholder
		[]string{
			"select 1 from t where param between 'value placeholder' and 3",
			"select 1 from t where param between 'value placeholder' and 'qwe'",
			"select 1 from t where param between 'value placeholder' and TRUE",
			"select 1 from t where param between 'value placeholder' and NULL",
			"select 1 from t where param between (select 1) and 2",
		},
		// right side value placeholder
		[]string{
			"select 1 from t where param between 2 and 'value placeholder'",
			"select 1 from t where param between 'qwe' and 'value placeholder'",
			"select 1 from t where param between TRUE and 'value placeholder'",
			"select 1 from t where param between NULL and 'value placeholder'",
			"select 1 from t where param between (select 1) and 'value placeholder'",
		},
		// two sides placeholder
		[]string{
			// incorrect column name
			"select 1 from t where incorrect_column between NULL and 'value placeholder'",
			"select 1 from t where param between (select 1) and (select 1)",
		}, // all queries should match
		// two explicit int values
		[]string{
			"select 1 from t where param between 1 and 3",
			"select 1 from t where param between 2 and 2",
			"select 1 from t where param between 1 and True",
			"select 1 from t where param between True and 2",
			"select 1 from t where param between 1 and Null",
			"select 1 from t where param between 2 and 1",
		},
		// two explicit str values
		[]string{
			"select 1 from t where param between 'qwe' and 1",
			"select 1 from t where param between 2 and 'asd'",
			"select 1 from t where param between True and 'asd'",
			"select 1 from t where param between 'qwe' and NULL",
		},
		// subqueries
		[]string{
			"select 1 from t where param between (select 1) and (select 1)",
			"select 1 from t where param between (select 2) and (select 2)",
		},
		// subqueries with %%SUBQUERY%% placeholder
		[]string{
			"select 1 from t where param between 1 and (select 1)",
			"select 1 from t where param between (select 1) and 1",
			"select 1 from t where param between (select 1) and someFunc()",
		},
		// subqueries with %%SUBQUERY%% and %%VALUE%% placeholders
		[]string{
			"select 1 from t where param between 'some value' and (select 'some query')",
			"select 1 from t where param between someFunc() and 'some value'",
		},
	}
	matchableQueries := [][]string{
		// left side value placeholder
		[]string{
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND 2",
			"SELECT 1 FROM t WHERE param BETWEEN 'qwe' AND 2",
			"SELECT 1 FROM t WHERE param BETWEEN TRUE AND 2",
			"SELECT 1 FROM t WHERE param BETWEEN FALSE AND 2",
			"SELECT 1 FROM t WHERE param BETWEEN NULL AND 2",
		},
		// right side value placeholder
		[]string{
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND 2",
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND 'qwe'",
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND TRUE",
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND FALSE",
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND NULL",
		},
		// two sides placeholder
		[]string{
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND 2",
			"SELECT 1 FROM t WHERE param BETWEEN NULL AND 'qwe'",
			"SELECT 1 FROM t WHERE param BETWEEN 'qwe' AND TRUE",
			"SELECT 1 FROM t WHERE param BETWEEN FALSE AND NULL",
		},
		// two explicit int values
		[]string{
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND 2",
		},
		// two explicit str values
		[]string{
			"SELECT 1 FROM t WHERE param BETWEEN 'qwe' and 'asd'",
		},
		// explicit subqueries
		[]string{
			"select 1 from t where param between (select 1) and (select 2)",
		},
		// subqueries with %%SUBQUERY%% placeholder
		[]string{
			"select 1 from t where param between (select 1) and (select 1)",
			"select 1 from t where param between (select 1) and (select 1 from table1 union select 2 from table2)",
		},
		// subqueries with %%SUBQUERY%% and %%VALUE%% placeholders
		[]string{
			"select 1 from t where param between (select 'some query') and 'some value'",
			"select 1 from t where param between (select 'some query') and 123",
			"select 1 from t where param between (select 'some query') and FALSE",
		},
	}
	if len(parsedPatterns) != len(matchableQueries) {
		t.Fatal("Mismatch test configuration")
	}
	for i := 0; i < len(parsedPatterns); i++ {
		pattern := parsedPatterns[i][0]
		patternRange := pattern.(*sqlparser.Select).Where.Expr.(*sqlparser.RangeCond)
		for _, query := range matchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatalf("Can't parse query <%s> with error <%s>", query, err.Error())
			}
			queryRange := parsedQuery.(*sqlparser.Select).Where.Expr.(*sqlparser.RangeCond)
			if !matchRangeCondition(patternRange, queryRange) {
				t.Fatalf("Expected match in query <%s> with pattern <%s>", query, sqlparser.String(pattern))
			}
		}

		for _, query := range notMatchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatal(err)
			}
			queryRange := parsedQuery.(*sqlparser.Select).Where.Expr.(*sqlparser.RangeCond)
			if matchRangeCondition(patternRange, queryRange) {
				t.Fatalf("Expected not match in query <%s> with pattern <%s>", query, sqlparser.String(pattern))
			}
		}
	}
}

// TestSkipSubqueryValuePattern test a=(%%SUBQUERY%%) pattern
func TestSkipSubqueryValuePattern(t *testing.T) {
	parsedPatterns, err := ParsePatterns([]string{
		fmt.Sprintf("select 1 from t where a=(%s)", SubqueryConfigPlaceholder),
	})
	if err != nil {
		t.Fatal(err)
	}
	patternSubexpr, ok := parsedPatterns[0][0].(*sqlparser.Select).Where.Expr.(*sqlparser.ComparisonExpr).Right.(*sqlparser.Subquery)
	if !ok {
		t.Fatal("Incorrect pattern format")
	}
	queries := []string{
		"Select 1 from t where a=(select column1, column2 from table1 where a=1)",
		"Select 1 from t where a=(select column1, column2 from table1 inner join table2 on table2.id=table1.id where a=1)",
		"Select 1 from t where a=(select column1, column2 from table1 where a=1 union select column1, column2 from table2)",
	}
	for _, query := range queries {
		parsedQuery, err := sqlparser.Parse(query)
		if err != nil {
			t.Fatalf("Can't parse query %s with error %s", query, err.Error())
		}
		querySubexpr, ok := parsedQuery.(*sqlparser.Select).Where.Expr.(*sqlparser.ComparisonExpr).Right.(*sqlparser.Subquery)
		if !ok {
			t.Fatal("Incorrect query syntax")
		}
		if !matchSubqueryPattern(patternSubexpr, querySubexpr) {
			t.Fatalf("Expected true result with query - %s", query)
		}
	}
}

// TestPatternsInWhereClauses test all patterns in WHERE clause
func TestPatternsInWhereClauses(t *testing.T) {
	patterns := []string{
		// left side value placeholder
		fmt.Sprintf("select 1 from t where param between %s and 2", ValueConfigPlaceholder),
		// left side value placeholder with other conditions
		fmt.Sprintf("select 1 from t where param1 = 2 and param between %s and 2 or param3='qwe'", ValueConfigPlaceholder),
		// right side value placeholder
		fmt.Sprintf("select 1 from t where param between 1 and %s", ValueConfigPlaceholder),
		// right side value placeholder with other conditions
		fmt.Sprintf("select 1 from t where param1 = 2 and param between 1 and %s or param1 = TRUE", ValueConfigPlaceholder),
		// two sides placeholder
		fmt.Sprintf("select 1 from t where param between %s and %s", ValueConfigPlaceholder, ValueConfigPlaceholder),
		// two sides placeholder with other conditions
		fmt.Sprintf("select 1 from t where param1 = 2 and param between %s and %s or param2 is NULL", ValueConfigPlaceholder, ValueConfigPlaceholder),
		// two explicit int values
		"select 1 from t where param between 1 and 2",
		// two explicit int values with other conditions
		"select 1 from t where b=2 and param between 1 and 2 and True",
		// two explicit str values
		"select 1 from t where param between 'qwe' and 'asd'",
		// two explicit str values with other conditions
		"select 1 from t where b='qwe' and param between 'qwe' and 'asd' and t in (1,2,3)",
		// IN clause with %%VALUE%% placeholders
		fmt.Sprintf("select 1 from t where b='qwe' and t IN (%s, %s, 1)", ValueConfigPlaceholder, ValueConfigPlaceholder),
		// IN clause with %%LIST_OF_VALUES%% placeholders
		fmt.Sprintf("select 1 from t where b='qwe' and t IN (%s)", ListOfValuesConfigPlaceholder),
		// IN clause with %%VALUE%% and %%LIST_OF_VALUES%% placeholders
		fmt.Sprintf("select 1 from t where b='qwe' and t IN (%s, 1, %s)", ValueConfigPlaceholder, ListOfValuesConfigPlaceholder),
		// column IN (%%SUBQUERY%%)
		fmt.Sprintf("select 1 from t where b='qwe' and t IN ((%s))", SubqueryConfigPlaceholder),
		// column IN (%%VALUE, %%SUBQUERY%%, 1, %%LIST_OF_VALUES%%)
		fmt.Sprintf("select 1 from t where b='qwe' and t IN (%s, (%s), 1, %s)", ValueConfigPlaceholder, SubqueryConfigPlaceholder, ListOfValuesConfigPlaceholder),
		// age = (%%SUBQUERY%%)
		fmt.Sprintf("select 1 from t where b='qwe' and a=(%s)", SubqueryConfigPlaceholder),
		// exists without patterns
		fmt.Sprintf("select 1 from t where exists(select 1) and a=2"),
		// exists with %%SUBQUERY%%
		fmt.Sprintf("select 1 from t where exists(%s) and a=2", SubqueryConfigPlaceholder),
	}
	parsedPatterns, err := ParsePatterns(patterns)
	if err != nil {
		t.Fatal(err)
	}
	notMatchableQueries := [][]string{
		// left side value placeholder
		[]string{
			"select 1 from t where param between 'value placeholder' and 3",
			"select 1 from t where param between 'value placeholder' and 'qwe'",
			"select 1 from t where param between 'value placeholder' and TRUE",
			"select 1 from t where param between 'value placeholder' and NULL",
		},
		// left side value placeholder with other conditions
		[]string{
			// incorrect param1
			"select 1 from t where param1 = 1 and param between 'value placeholder' and 2 or param3='qwe'",
			// incorrect right value
			"select 1 from t where param1 = 2 and param between 'value placeholder' and 3 or param3='qwe'",
			// incorrect param3
			"select 1 from t where param1 = 2 and param between 'value placeholder' and 2 or param3='incorrect'",
		},
		// right side value placeholder
		[]string{
			"select 1 from t where param between 2 and 'value placeholder'",
			"select 1 from t where param between 'qwe' and 'value placeholder'",
			"select 1 from t where param between TRUE and 'value placeholder'",
			"select 1 from t where param between NULL and 'value placeholder'",
		},
		// right side value placeholder with other conditions
		[]string{
			// incorrect param1
			"select 1 from t where param1 = 1 and param between 1 and 1 or param1 = TRUE",
			// incorrect param1
			"select 1 from t where param1 = 2 and param between 1 and 'qwe' or param1 = FALSE",
			// incorrect left param
			"select 1 from t where param1 = 2 and param between 2 and TRUE or param1 = TRUE",
		},

		// two sides placeholder
		[]string{}, // all queries should match
		// two sides placeholder with other conditions
		[]string{
			// incorrect param1
			"select 1 from t where param1 = 1 and param between 'asd' and 1 or param1 = TRUE",
			// incorrect param1
			"select 1 from t where param1 = 2 and param between 1 and 'qwe' or param1 = FALSE",
		},
		// two explicit int values
		[]string{
			"select 1 from t where param between 1 and 3",
			"select 1 from t where param between 2 and 2",
			"select 1 from t where param between 1 and 'qwe'",
			"select 1 from t where param between 1 and NULL",
			"select 1 from t where param between 1 and TRUE",
		},
		// two explicit int values with other conditions
		[]string{
			// incorrect right condition
			"select 1 from t where b=2 and param between 1 and 3 and True",
			// incorrect left condition
			"select 1 from t where b=2 and param between 2 and 2 and True",
			// incorrect right param
			"select 1 from t where b=2 and param between 1 and 2 and False",
			// incorrect b param
			"select 1 from t where b=1 and param between 1 and 2 and True",
		},
		// two explicit str values
		[]string{
			// incorrect right condition
			"select 1 from t where param between 'qwe' and 'incorrect'",
			// incorrect left condition
			"select 1 from t where param between 'incorrect' and 'asd'",
			// incorrect right condition value type
			"select 1 from t where param between 'qwe' and 1",
			// incorrect right condition value type
			"select 1 from t where param between 1 and 'asd'",
		},
		// two explicit str values with other conditions
		[]string{
			// "select 1 from t where b='qwe' and param between 'qwe' and 'asd' and t in (1,2,3)",
			// incorrect t in ()
			"select 1 from t where b='qwe' and param between 'qwe' and 'asd' and t in (1,2,2)",
			// incorrect b
			"select 1 from t where b=1 and param between 'qwe' and 'asd' and t in (1,2,3)",
			// incorrect left condition
			"select 1 from t where b='qwe' and param between 1 and 'asd' and t in (1,2,3)",
			// incorrect right condition
			"select 1 from t where b='qwe' and param between 'qwe' and 1 and t in (1,2,3)",
			// incorrect column of between
			"select 1 from t where b='qwe' and incorrect_column between 'qwe' and 'asd' and t in (1,2,3)",
		},
		// IN clause with %%VALUE%% placeholders
		[]string{
			// incorrect specific value
			"select 1 from t where b='qwe' and t IN (1, 'qwe', 2)",
			// subquery instead value
			"select 1 from t where b='qwe' and t IN ((select 1), NULL, 1)",
			// another length of list
			"select 1 from t where b='qwe' and t IN (1, 2, 1, 1)",
		},
		// IN clause with %%LIST_OF_VALUES%% placeholders
		[]string{}, // any length of list is acceptable
		// IN clause with %%VALUE%% and %%LIST_OF_VALUES%% placeholders
		[]string{
			// incorrect specific value
			"select 1 from t where b='qwe' and t IN (1, 2, 1)",
			// subquery as value
			"select 1 from t where b='qwe' and t IN ((select 1), 1, 2)",
			// empty values on list of values
			"select 1 from t where b='qwe' and t IN (1, 1)",
		},

		// column IN (%%SUBQUERY%%)
		[]string{
			// anything except subquery
			"select 1 from t where b='qwe' and t IN (1)",
		},

		// column IN (%%VALUE, %%SUBQUERY%%, 1, %%LIST_OF_VALUES%%)
		[]string{
			// anything except subquery on subquery placeholder
			"select 1 from t where b='qwe' and t IN (1, 2, 1, 3)",
		},
		// age = (%%SUBQUERY%%)
		[]string{
			// not subquery
			"select 1 from t where b='qwe' and a=1",
			// func instead subquery
			"select 1 from t where b='qwe' and a=someFunc(2)",
		},
		// exists without patterns
		[]string{
			// different query in exists
			"select 1 from t where exists(select 2) and a=2",
		},
		// exists with %%SUBQUERY%%
		[]string{
			// func instead exists
			"select 1 from t where someFunc(1) and a=2",
			// another value in second param
			"select 1 from t where exists(select 1) and a=3",
		},
	}
	matchableQueries := [][]string{
		// left side value placeholder
		[]string{
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND 2",
			"SELECT 1 FROM t WHERE param BETWEEN 'qwe' AND 2",
			"SELECT 1 FROM t WHERE param BETWEEN TRUE AND 2",
			"SELECT 1 FROM t WHERE param BETWEEN NULL AND 2",
		},
		// left side value placeholder with other conditions
		[]string{
			"select 1 from t where param1 = 2 and param between 1 and 2 or param3='qwe'",
			"select 1 from t where param1 = 2 and param between 'qwe' and 2 or param3='qwe'",
			"select 1 from t where param1 = 2 and param between TRUE and 2 or param3='qwe'",
			"select 1 from t where param1 = 2 and param between NULL and 2 or param3='qwe'",
		},
		// right side value placeholder
		[]string{
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND 2",
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND 'qwe'",
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND TRUE",
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND NULL",
		},
		// right side value placeholder with other conditions
		[]string{
			// incorrect param1
			"select 1 from t where param1 = 2 and param between 1 and 1 or param1 = TRUE",
			// incorrect param1
			"select 1 from t where param1 = 2 and param between 1 and 'qwe' or param1 = TRUE",
			// incorrect left param
			"select 1 from t where param1 = 2 and param between 1 and TRUE or param1 = TRUE",
		},
		// two sides placeholder
		[]string{
			"select 1 from t where param between TRUE and 1",
			"select 1 from t where param between TRUE and 'qwe'",
			"select 1 from t where param between NULL and FALSE",
			"select 1 from t where param between 'qwe' and 2",
		},
		// two sides placeholder with other conditions
		[]string{
			"select 1 from t where param1 = 2 and param between TRUE and 1 or param2 is NULL",
			"select 1 from t where param1 = 2 and param between TRUE and 'qwe' or param2 is NULL",
			"select 1 from t where param1 = 2 and param between NULL and FALSE or param2 is NULL",
			"select 1 from t where param1 = 2 and param between 'qwe' and 2 or param2 is NULL",
		},
		// two explicit int values
		[]string{
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND 2",
		},
		// two explicit int values with other conditions
		[]string{
			"select 1 from t where b=2 and param between 1 and 2 and True",
		},
		// two explicit str values
		[]string{
			"select 1 from t where param between 'qwe' and 'asd'",
		},
		// two explicit str values with other conditions
		[]string{
			"select 1 from t where b='qwe' and param between 'qwe' and 'asd' and t in (1,2,3)",
		},
		// IN clause with %%VALUE%% placeholders
		[]string{
			// int, str
			"select 1 from t where b='qwe' and t IN (1, 'qwe', 1)",
			// boolean, nullable
			"select 1 from t where b='qwe' and t IN (FALSE, NULL, 1)",
		},
		// IN clause with %%LIST_OF_VALUES%% placeholders
		[]string{
			// one value
			"select 1 from t where b='qwe' and t IN (1)",
			// many values
			"select 1 from t where b='qwe' and t IN (1, 'qwe', True, NULL, FALSE)",
		},

		// IN clause with %%VALUE%% and %%LIST_OF_VALUES%% placeholders
		[]string{
			// one value as list of values
			"select 1 from t where b='qwe' and t IN ('qwe', 1, 1)",
			// many values as list of values
			"select 1 from t where b='qwe' and t IN ('qwe', 1, 1, True, NULL, FALSE)",
		},

		// column IN (%%SUBQUERY%%)
		[]string{
			"select 1 from t where b='qwe' and t IN ((select 1))",
			"select 1 from t where b='qwe' and t IN ((select 1 from table1))",
			"select 1 from t where b='qwe' and t IN ((select column1 from table1 where a=1 union select column1 from table2 where b=1))",
		},

		// column IN (%%VALUE, %%SUBQUERY%%, 1, %%LIST_OF_VALUES%%)
		[]string{
			"select 1 from t where b='qwe' and t IN (1, (select 1), 1, 1, 2)",
			"select 1 from t where b='qwe' and t IN (1, (select 1 from table1), 1, 1, 2)",
			"select 1 from t where b='qwe' and t IN (1, (select column1 from table1 where a=1 union select column1 from table2 where b=1), 1, 1, 2)",
		},
		// age = (%%SUBQUERY%%)
		[]string{
			"select 1 from t where b='qwe' and a=(select 1)",
			"select 1 from t where b='qwe' and a=(select 1 from table1 union select 2 from table2)",
		},
		// exists without patterns
		[]string{
			// different query in exists
			"select 1 from t where exists(select 1) and a=2",
		},
		// exists with %%SUBQUERY%%
		[]string{
			// simple query
			"select 1 from t where exists(select 1) and a=2",
			// query with union
			"select 1 from t where exists(select 1 from table1 union select 2 from table2) and a=2",
		},
	}
	if len(patterns) != len(matchableQueries) || len(matchableQueries) != len(notMatchableQueries) {
		t.Fatal("Mismatch test configuration with incorrect array dimensions")
	}

	for i := 0; i < len(parsedPatterns); i++ {
		pattern := parsedPatterns[i][0]
		for _, query := range matchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatalf("Can't parse query <%s> with error <%s>", query, err.Error())
			}
			if !handleWherePatterns([]sqlparser.SQLNode{parsedQuery}, []sqlparser.SQLNode{pattern}) {
				t.Fatalf("Expected match in query <%s> with pattern <%s>", query, sqlparser.String(pattern))
			}
		}

		for _, query := range notMatchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatalf("Error <%s> with query <%s>", err.Error(), query)
			}
			if handleWherePatterns([]sqlparser.SQLNode{parsedQuery}, []sqlparser.SQLNode{pattern}) {
				t.Fatalf("Expected not match in query <%s> with pattern <%s>", query, sqlparser.String(pattern))
			}
		}
	}
}

func TestOrderByWithColumnPattern(t *testing.T) {
	patterns := []string{
		// ORDER BY with column placeholder
		fmt.Sprintf("SELECT a1 FROM table1 ORDER BY %s", ColumnConfigPlaceholder),
	}

	parsedPatterns, err := ParsePatterns(patterns)
	if err != nil {
		t.Fatal(err)
	}

	matchableQueries := [][]string{
		[]string{
			"SELECT a1 FROM table1 ORDER BY column1",
			"SELECT a1 FROM table1 ORDER BY 1",
			"SELECT a1 FROM table1 ORDER BY (select priority from ordering o where o.val = e.name)",
			"SELECT a1 FROM table1 ORDER BY Date()",
			"SELECT a1 FROM table1 ORDER BY (case when f1 then 1 when f1 is null then 2 else 3 end)",
		},
	}

	notMatchableQueries := [][]string{
		[]string{
			"SELECT a1 FROM table1 ORDER BY column1 DESC",
			"SELECT a1 FROM table1 ORDER BY 1 DESC",
			"SELECT a1 FROM table1 ORDER BY column1, column2",
			"SELECT a1 FROM table1 ORDER BY Date() DESC",
			"SELECT a1 FROM table1 ORDER BY (case when f1 then 1 when f1 is null then 2 else 3 end), a2",
			"SELECT a1 FROM table1 ORDER BY (case when f1 then 1 when f1 is null then 2 else 3 end) DESC",
		},
	}

	if len(parsedPatterns) != len(matchableQueries) {
		t.Fatal("Mismatch test configuration")
	}

	for i, _ := range parsedPatterns {
		patternOrderBy := parsedPatterns[i][0].(*sqlparser.Select).OrderBy
		for _, query := range matchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatal(err)
			}
			queryOrderBy := parsedQuery.(*sqlparser.Select).OrderBy
			if !matchOrderBy(patternOrderBy, queryOrderBy) {
				t.Fatalf("Expected match in query <%s> with pattern <%s>", query, sqlparser.String(parsedPatterns[i][0]))
			}
		}

		for _, query := range notMatchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatal(err)
			}
			queryOrderBy := parsedQuery.(*sqlparser.Select).OrderBy
			if matchOrderBy(patternOrderBy, queryOrderBy) {
				t.Fatalf("Expected not match in query <%s> with pattern <%s>", query, sqlparser.String(parsedPatterns[i][0]))
			}
		}
	}
}

func TestSingleQueryPatternMatch(t *testing.T) {

	pattern := "SELECT %%COLUMN%% FROM testTable ORDER BY %%COLUMN%%"

	query := "SELECT x FROM testTable ORDER BY Date()"

	parsedPatterns, err := ParsePatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}

	match, err := checkPatternsMatching(parsedPatterns, query)
	if match {
		fmt.Println("match")
	} else {
		fmt.Println("not match")
	}

}
