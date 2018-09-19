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
		// right side value placeholder
		[]string{
			"select 1 from t where param between 2 and 'value placeholder'",
			"select 1 from t where param between 'qwe' and 'value placeholder'",
			"select 1 from t where param between TRUE and 'value placeholder'",
			"select 1 from t where param between NULL and 'value placeholder'",
		},
		// two sides placeholder
		[]string{
			// incorrect column name
			"select 1 from t where incorrect_column between NULL and 'value placeholder'",
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
	}
	matchableQueries := [][]string{
		// left side value placeholder
		[]string{
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND 2",
			"SELECT 1 FROM t WHERE param BETWEEN 'qwe' AND 2",
			"SELECT 1 FROM t WHERE param BETWEEN TRUE AND 2",
			"SELECT 1 FROM t WHERE param BETWEEN NULL AND 2",
		},
		// right side value placeholder
		[]string{
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND 2",
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND 'qwe'",
			"SELECT 1 FROM t WHERE param BETWEEN 1 AND TRUE",
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
				t.Fatal(err)
			}
			queryRange := parsedQuery.(*sqlparser.Select).Where.Expr.(*sqlparser.RangeCond)
			if !handleRangeCondition(patternRange, queryRange) {
				t.Fatalf("Expected match in query <%s> with pattern <%s>", query, sqlparser.String(pattern))
			}
		}

		for _, query := range notMatchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatal(err)
			}
			queryRange := parsedQuery.(*sqlparser.Select).Where.Expr.(*sqlparser.RangeCond)
			if handleRangeCondition(patternRange, queryRange) {
				t.Fatalf("Expected not match in query <%s> with pattern <%s>", query, sqlparser.String(pattern))
			}
		}
	}
}

func TestHandleValuePatternWithRangeCondition(t *testing.T) {
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
	}
	if len(patterns) != len(matchableQueries) || len(matchableQueries) != len(notMatchableQueries) {
		t.Fatal("Mismatch test configuration with incorrect array dimensions")
	}

	for i := 0; i < len(parsedPatterns); i++ {
		pattern := parsedPatterns[i][0]
		for _, query := range matchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatal(err)
			}
			if !handleValuePattern([]sqlparser.SQLNode{parsedQuery}, []sqlparser.SQLNode{pattern}) {
				t.Fatalf("Expected match in query <%s> with pattern <%s>", query, sqlparser.String(pattern))
			}
		}

		for _, query := range notMatchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatalf("Error <%s> with query <%s>", err.Error(), query)
			}
			if handleValuePattern([]sqlparser.SQLNode{parsedQuery}, []sqlparser.SQLNode{pattern}) {
				t.Fatalf("Expected not match in query <%s> with pattern <%s>", query, sqlparser.String(pattern))
			}
		}
	}

}
