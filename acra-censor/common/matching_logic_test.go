package common

import (
	"fmt"
	"github.com/xwb1989/sqlparser"
	"testing"
)

var testQueries = []string{
	// Union
	"SELECT x1 FROM x2 UNION SELECT x3 FROM x4",
	// Select
	"SELECT 1",
	// Insert (Insert)
	"INSERT INTO Customers (CustomerName, ContactName) VALUES ('Cardinal', 'Tom B. Erichsen')",
	// Insert (Replace)
	"REPLACE INTO test VALUES (1, 'Old', '2014-08-20 18:47:00')",
	// Update
	"UPDATE Customers SET ContactName = 'Alfred Schmidt', City = 'Frankfurt' WHERE CustomerID = 1",
	// Delete
	"DELETE FROM Customers WHERE CustomerName = 'Alfreds Futterkiste'",
	// Set
	"SET x = 2",
	//DBDDL (Create database)
	"CREATE DATABASE demo",
	//DBDDL (Drop database)
	"DROP DATABASE demo",
	// DDL (Create table)
	"CREATE TABLE Persons (PersonID int, LastName varchar(255), FirstName varchar(255), Address varchar(255), City varchar(255))",
	// DDL (Drop table)
	"DROP TABLE Shippers",
	// Show
	"SHOW PRIVILEGES",
	// Use
	"USE demo",
	// Begin
	"BEGIN",
	// Commit
	"COMMIT",
	// Rollback
	"ROLLBACK",
	// OtherRead (Describe)
	"DESCRIBE City",
	// OtherRead (Explain)
	"EXPLAIN SELECT * FROM x",
	// OtherAdmin (Repair)
	"REPAIR TABLE x",
	// OtherAdmin (Truncate)
	"TRUNCATE TABLE x",
	// OtherAdmin (Optimize)
	"OPTIMIZE TABLE x",
}

// TestMatchTopLevelPlaceholders tests top level patterns
func TestMatchTopLevelPlaceholders(t *testing.T) {
	testSingleTopLevelPlaceholder(t, "%%UNION%%", 0)
	testSingleTopLevelPlaceholder(t, "%%SELECT%%", 1)
	testSingleTopLevelPlaceholder(t, "%%INSERT%%", 2, 3)
	testSingleTopLevelPlaceholder(t, "%%UPDATE%%", 4)
	testSingleTopLevelPlaceholder(t, "%%DELETE%%", 5)

	testSingleTopLevelPlaceholder(t, "%%BEGIN%%", 13)
	testSingleTopLevelPlaceholder(t, "%%COMMIT%%", 14)
	testSingleTopLevelPlaceholder(t, "%%ROLLBACK%%", 15)

}
func testSingleTopLevelPlaceholder(t *testing.T, pattern string, indexOfMatchedQuery ...int) {
	parsedPatterns, err := ParsePatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}
	match := false
	for index := range testQueries {

		stmt, err := sqlparser.Parse(testQueries[index])
		if err != nil {
			t.Fatal(err)
		}

		match = CheckPatternsMatching(parsedPatterns, stmt)
		if contains(indexOfMatchedQuery, index) {
			if !match {
				t.Fatalf("Expected match in query <%s> with pattern <%s>", testQueries[index], pattern)
			}
		} else {
			if match {
				t.Fatalf("Expected not match in query <%s> with pattern <%s>", testQueries[index], pattern)
			}
		}
	}
}
func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// TestHandleRangeCondition test queries with "column BETWEEN VALUE1 and VALUE2"
func TestHandleRangeCondition(t *testing.T) {
	patterns := []string{
		// left side value placeholder
		fmt.Sprintf("select 1 from t where param between %s and 2", ValuePlaceholder),
		// right side value placeholder
		fmt.Sprintf("select 1 from t where param between 1 and %s", ValuePlaceholder),
		// two sides placeholder
		fmt.Sprintf("select 1 from t where param between %s and %s", ValuePlaceholder, ValuePlaceholder),
		// two explicit int values
		"select 1 from t where param between 1 and 2",
		// two explicit str values
		"select 1 from t where param between 'qwe' and 'asd'",
		// subqueries instead values
		"select 1 from t where param between (select 1) and (select 2)",
		// subqueries with %%SUBQUERY%% placeholder
		fmt.Sprintf("select 1 from t where param between (%s) and (%s)", SubqueryPlaceholder, SubqueryPlaceholder),
		// subqueries with %%SUBQUERY%% and %%VALUE%% placeholders
		fmt.Sprintf("select 1 from t where param between (%s) and %s", SubqueryPlaceholder, ValuePlaceholder),
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
		pattern := parsedPatterns[i]
		for _, query := range matchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatalf("Can't parse query <%s> with error <%s>", query, err.Error())
			}
			if !checkSinglePatternMatch(parsedQuery, pattern) {
				t.Fatalf("Expected match in query <%s> with pattern <%s>", query, sqlparser.String(pattern))
			}
		}

		for _, query := range notMatchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatal(err)
			}
			if checkSinglePatternMatch(parsedQuery, pattern) {
				t.Fatalf("Expected not match in query <%s> with pattern <%s>", query, sqlparser.String(pattern))
			}
		}
	}
}

// TestSkipSubqueryValuePattern test a=(%%SUBQUERY%%) pattern
func TestSkipSubqueryValuePattern(t *testing.T) {
	parsedPatterns, err := ParsePatterns([]string{
		fmt.Sprintf("select 1 from t where a=(%s)", SubqueryPlaceholder),
	})
	if err != nil {
		t.Fatal(err)
	}
	patternSubexpr, ok := parsedPatterns[0].(*sqlparser.Select).Where.Expr.(*sqlparser.ComparisonExpr).Right.(*sqlparser.Subquery)
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
		if !areEqualSubquery(querySubexpr, patternSubexpr) {
			t.Fatalf("Expected true result with query - %s", query)
		}
	}
}

// TestPatternsInWhereClauses test all patterns in WHERE clause
func TestPatternsInWhereClauses(t *testing.T) {
	patterns := []string{
		// left side value placeholder
		fmt.Sprintf("select 1 from t where param between %s and 2", ValuePlaceholder),
		// left side value placeholder with other conditions
		fmt.Sprintf("select 1 from t where param1 = 2 and param between %s and 2 or param3='qwe'", ValuePlaceholder),
		// right side value placeholder
		fmt.Sprintf("select 1 from t where param between 1 and %s", ValuePlaceholder),
		// right side value placeholder with other conditions
		fmt.Sprintf("select 1 from t where param1 = 2 and param between 1 and %s or param1 = TRUE", ValuePlaceholder),
		// two sides placeholder
		fmt.Sprintf("select 1 from t where param between %s and %s", ValuePlaceholder, ValuePlaceholder),
		// two sides placeholder with other conditions
		fmt.Sprintf("select 1 from t where param1 = 2 and param between %s and %s or param2 is NULL", ValuePlaceholder, ValuePlaceholder),
		// two explicit int values
		"select 1 from t where param between 1 and 2",
		// two explicit int values with other conditions
		"select 1 from t where b=2 and param between 1 and 2 and True",
		// two explicit str values
		"select 1 from t where param between 'qwe' and 'asd'",
		// two explicit str values with other conditions
		"select 1 from t where b='qwe' and param between 'qwe' and 'asd' and t in (1,2,3)",
		// IN clause with %%VALUE%% placeholders
		fmt.Sprintf("select 1 from t where b='qwe' and t IN (%s, %s, 1)", ValuePlaceholder, ValuePlaceholder),
		// IN clause with %%LIST_OF_VALUES%% placeholders
		fmt.Sprintf("select 1 from t where b='qwe' and t IN (%s)", ListOfValuesPlaceholder),
		// IN clause with %%VALUE%% and %%LIST_OF_VALUES%% placeholders
		fmt.Sprintf("select 1 from t where b='qwe' and t IN (%s, 1, %s)", ValuePlaceholder, ListOfValuesPlaceholder),
		// column IN (%%SUBQUERY%%)
		fmt.Sprintf("select 1 from t where b='qwe' and t IN ((%s))", SubqueryPlaceholder),
		// column IN (%%VALUE, %%SUBQUERY%%, 1, %%LIST_OF_VALUES%%)
		fmt.Sprintf("select 1 from t where b='qwe' and t IN (%s, (%s), 1, %s)", ValuePlaceholder, SubqueryPlaceholder, ListOfValuesPlaceholder),
		// age = (%%SUBQUERY%%)
		fmt.Sprintf("select 1 from t where b='qwe' and a=(%s)", SubqueryPlaceholder),
		// exists without patterns
		fmt.Sprintf("select 1 from t where exists(select 1) and a=2"),
		// exists with %%SUBQUERY%%
		fmt.Sprintf("select 1 from t where exists(%s) and a=2", SubqueryPlaceholder),
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
		pattern := parsedPatterns[i]
		for _, query := range matchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatalf("Can't parse query <%s> with error <%s>", query, err.Error())
			}
			if !checkSinglePatternMatch(parsedQuery, pattern) {
				t.Fatalf("Expected match in query <%s> with pattern <%s>", query, sqlparser.String(pattern))
			}
		}

		for _, query := range notMatchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatalf("Error <%s> with query <%s>", err.Error(), query)
			}
			if checkSinglePatternMatch(parsedQuery, pattern) {
				t.Fatalf("Expected not match in query <%s> with pattern <%s>", query, sqlparser.String(pattern))
			}
		}
	}
}

// TestOrderByWithColumnPattern tests %%COLUMN%% pattern in GroupBy statement
func TestGroupByWithColumnPattern(t *testing.T) {
	patterns := []string{
		// GROUP BY with column placeholder
		fmt.Sprintf("SELECT a1 FROM table1 GROUP BY %s", ColumnPlaceholder),
		fmt.Sprintf("SELECT a FROM b GROUP BY a, %s, 1, %s", ColumnPlaceholder, ColumnPlaceholder),
	}

	parsedPatterns, err := ParsePatterns(patterns)
	if err != nil {
		t.Fatal(err)
	}

	matchableQueries := [][]string{
		[]string{
			"SELECT a1 FROM table1 GROUP BY column1",
			"SELECT a1 FROM table1 GROUP BY 1",
			"SELECT a1 FROM table1 GROUP BY (select priority from ordering o where o.val = e.name)",
			"SELECT a1 FROM table1 GROUP BY Date()",
			"SELECT a1 FROM table1 GROUP BY (case when f1 then 1 when f1 is null then 2 else 3 end)",
		},
		[]string{
			"select a from b group by a, 2, 1, ABC",
		},
	}

	notMatchableQueries := [][]string{
		[]string{
			// two columns
			"SELECT a1 FROM table1 GROUP BY column1, column2",
		},
		[]string{
			"SELECT a from b GROUP BY 1, abc, 1, abs",
			"SELECT a from b GROUP BY a, abc, b, ABC",
			"SELECT a from b GROUP BY a, abc, 1, ABC, ABC",
		},
	}

	if len(parsedPatterns) != len(matchableQueries) {
		t.Fatal("Mismatch test configuration")
	}

	for i := 0; i < len(parsedPatterns); i++ {
		patternGroupBy := parsedPatterns[i].(*sqlparser.Select).GroupBy
		for _, query := range matchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatal(err)
			}
			queryGroupBy := parsedQuery.(*sqlparser.Select).GroupBy
			if !areEqualGroupBy(queryGroupBy, patternGroupBy) {
				t.Fatalf("Expected match in query <%s> with pattern <%s>", query, sqlparser.String(parsedPatterns[i]))
			}
		}

		for _, query := range notMatchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatal(err)
			}
			queryGroupBy := parsedQuery.(*sqlparser.Select).GroupBy
			if areEqualGroupBy(queryGroupBy, patternGroupBy) {
				t.Fatalf("Expected not match in query <%s> with pattern <%s>", query, sqlparser.String(parsedPatterns[i]))
			}
		}
	}
}

// TestOrderByWithColumnPattern tests %%COLUMN%% and %%VALUE%% patterns in Having statement
func TestHavingWithColumnAndValueMatch(t *testing.T) {
	patterns := []string{
		fmt.Sprintf("SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(%s) > 100", ColumnPlaceholder),
		fmt.Sprintf("SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a3) > %s", ValuePlaceholder),
		fmt.Sprintf("SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(%s) > %s", ColumnPlaceholder, ValuePlaceholder),
	}

	parsedPatterns, err := ParsePatterns(patterns)
	if err != nil {
		t.Fatal(err)
	}

	matchableQueries := [][]string{
		[]string{
			"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a) > 100",
			"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(*) > 100",
		},
		[]string{
			"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a3) > 100",
			"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a3) > 200.0",
			"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a3) > NULL",
		},
		[]string{
			"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a3) > 0",
			"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a2) > 1000",
			"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a1) > TRUE",
		},
	}

	notMatchableQueries := [][]string{
		[]string{
			// GroupBy not match
			"SELECT a1 FROM table1 GROUP BY a3 HAVING COUNT(a) > 100",
			// Comparison inside Having not match
			"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a) < 100",
		},
		[]string{
			// Wrong ColName inside FuncExpr of Having
			"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a1) > 100",
			// Wrong ComparisonExpr inside Having
			"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a3) < 200.0",
			// Wrong GroupBy column
			"SELECT a1 FROM table1 GROUP BY a3 HAVING COUNT(a3) > NULL",
			// Subquery as value
			"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a3) > (select 1)",
		},
		[]string{
			// 2 columns inside FuncExpr
			"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a1, a2) > 10",
			// Wrong FuncExpr name
			"SELECT a1 FROM table1 GROUP BY a2 HAVING MIN(a1) > 1000",
			// Wrong ComparisonExpr inside Having
			"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a10) < 1000",
			// Subquery as value
			"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a10) > (select 1)",
		},
	}

	if len(parsedPatterns) != len(matchableQueries) {
		t.Fatal("Mismatch test configuration")
	}

	for i := 0; i < len(parsedPatterns); i++ {
		for _, query := range matchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatal(err)
			}

			if !checkSinglePatternMatch(parsedQuery, parsedPatterns[i]) {
				t.Fatalf("Expected match in query <%s> with pattern <%s>", query, sqlparser.String(parsedPatterns[i]))
			}
		}

		for _, query := range notMatchableQueries[i] {
			parsedQuery, err := sqlparser.Parse(query)
			if err != nil {
				t.Fatal(err)
			}

			if checkSinglePatternMatch(parsedQuery, parsedPatterns[i]) {
				t.Fatalf("Expected not match in query <%s> with pattern <%s>", query, sqlparser.String(parsedPatterns[i]))
			}
		}
	}
}
