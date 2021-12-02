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

// Package acracensor represents separate firewall module for Acra. AcraCensor handles each query that
// gets through AcraServer. You can setup the whitelist and the blacklist separately or simultaneously.
// The order of priority for the lists is defined by their order in the configuration file.
// Priority of work for one of the lists is the following: queries, followed by tables, followed by rules.
//
// https://github.com/cossacklabs/acra/wiki/AcraCensor
package acracensor

import (
	"bytes"
	"encoding/json"
	"github.com/cossacklabs/acra/acra-censor/common"
	"github.com/cossacklabs/acra/sqlparser"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"fmt"
	"github.com/cossacklabs/acra/acra-censor/handlers"
	"github.com/cossacklabs/acra/utils"
)

func TestAllowQueries(t *testing.T) {
	var err error
	sqlSelectQueries := []string{
		"SELECT Student_ID FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT EMP_ID, NAME FROM EMPLOYEE_TBL WHERE EMP_ID = '0000';",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"SELECT Name, Age FROM Patients WHERE Age > 40 GROUP BY Age ORDER BY Name;",
		"SELECT COUNT(CustomerID), Country FROM Customers GROUP BY Country;",
		"SELECT SUM(Salary)FROM Employee WHERE Emp_Age < 30;",
		"SELECT AVG(Price)FROM Products;",
	}
	sqlInsertQueries := []string{
		"INSERT SalesStaff1 VALUES (2, 'Michael', 'Blythe'), (3, 'Linda', 'Mitchell'),(4, 'Jillian', 'Carson'), (5, 'Garrett', 'Vargas');",
		"INSERT INTO SalesStaff2 (StaffGUID, FirstName, LastName) VALUES (NEWID(), 'Stephen', 'Jiang');",
		"INSERT INTO SalesStaff3 (StaffID, FullName) VALUES (X, 'Y');",
		"INSERT INTO SalesStaff3 (StaffID, FullName) VALUES (X, 'Z');",
		"INSERT INTO SalesStaff3 (StaffID, FullNameTbl) VALUES (X, M);",
		"INSERT INTO X.Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"INSERT INTO Production (Name, UnitMeasureCode,	ModifiedDate) VALUES ('Square Yards', 'Y2', GETDATE());",
		"INSERT INTO T1 (Name, UnitMeasureCode,	ModifiedDate) VALUES ('Square Yards', 'Y2', GETDATE());",
		"INSERT INTO dbo.Points (Type, PointValue) VALUES ('Point', '1,5');",
		"INSERT INTO dbo.Points (PointValue) VALUES ('1,99');",
	}

	whitelistHandler := handlers.NewAllowHandler(sqlparser.New(sqlparser.ModeStrict))
	whitelistHandler.AddQueries(sqlSelectQueries)
	whitelistHandler.AddQueries(sqlInsertQueries)
	acraCensor := NewAcraCensor()
	defer acraCensor.ReleaseAll()
	//set our acracensor to use whitelist for query evaluating
	acraCensor.AddHandler(whitelistHandler)
	acraCensor.AddHandler(handlers.NewDenyallHandler())
	//acracensor should not block those queries
	for _, query := range sqlSelectQueries {
		err = acraCensor.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, query := range sqlInsertQueries {
		err = acraCensor.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}
	//acracensor should block this query because it is not in whitelist
	err = acraCensor.HandleQuery("SELECT * FROM testDB.testTbl;")
	if err != common.ErrDenyAllError {
		t.Fatal(err)
	}
	//ditto
	err = acraCensor.HandleQuery("INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');")
	if err != common.ErrDenyAllError {
		t.Fatal(err)
	}

	//acracensor should NOT block this query because its the same as in whitelist, but lower-cased and without ";"
	lowerCaseWhiteListedQuery := "select * from STUDENT"
	err = acraCensor.HandleQuery(lowerCaseWhiteListedQuery)
	if err != nil {
		t.Fatal(err)
	}
	//acracensor should NOT block this query because its the same as in whitelist, but lower-cased and without ;
	err = acraCensor.HandleQuery("select EMP_ID, LAST_NAME from EMPLOYEE where CITY = 'Seattle' order BY EMP_ID")
	if err != nil {
		t.Fatal(err)
	}

	whitelistHandler.RemoveQueries([]string{lowerCaseWhiteListedQuery})
	err = acraCensor.HandleQuery(lowerCaseWhiteListedQuery)
	//now acracensor should block this query because it is not in whitelist anymore
	if err != common.ErrDenyAllError {
		t.Fatal(err)
	}
}
func TestAllowTables(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()

	whitelistHandler := handlers.NewAllowHandler(sqlparser.New(sqlparser.ModeStrict))
	censor.AddHandler(whitelistHandler)
	censor.AddHandler(handlers.NewDenyallHandler())

	testQueries := []string{
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"INSERT INTO Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL AS EMPL_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
	}
	//whitelistHandler.AddQueries(testQueries)
	whitelistHandler.AddTables([]string{"EMPLOYEE"})
	queryIndexesToBlock := []int{0, 2, 3, 4, 5, 6}
	//acracensor should block those queries
	for _, i := range queryIndexesToBlock {
		err := censor.HandleQuery(testQueries[i])
		if err != common.ErrDenyAllError {
			t.Fatal(err)
		}
	}
	whitelistHandler.AddTables([]string{"Customers"})
	// now we should allow query that access EMPLOYEE or Customers tables and deny all others
	queryIndexesToPass := []int{1, 4, 5}
	for _, i := range queryIndexesToPass {
		err = censor.HandleQuery(testQueries[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	//Now we have no tables in whitelist, so censor should block all queries
	whitelistHandler.RemoveTables([]string{"EMPLOYEE", "Customers"})
	for _, query := range testQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyAllError {
			t.Fatal(err)
		}
	}
	testQuery := "SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL, CUSTOMERS WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;"
	whitelistHandler.AddTables([]string{"EMPLOYEE", "EMPLOYEE_TBL"})
	err = censor.HandleQuery(testQuery)
	//acracensor should block this query
	if err != common.ErrDenyAllError {
		t.Fatal(err)
	}
	whitelistHandler.AddTables([]string{"CUSTOMERS"})
	err = censor.HandleQuery(testQuery)
	//acracensor should not block this query
	if err != nil {
		t.Fatal(err)
	}
}
func TestAllowSelectPattern(t *testing.T) {
	var err error
	testQueries := []string{
		"INSERT SalesStaff1 VALUES (2, 'Michael', 'Blythe'), (3, 'Linda', 'Mitchell'),(4, 'Jillian', 'Carson'), (5, 'Garrett', 'Vargas');",
		"INSERT INTO SalesStaff2 (StaffGUID, FirstName, LastName) VALUES (NEWID(), 'Stephen', 'Jiang');",
		"INSERT INTO SalesStaff3 (StaffID, FullNameTbl) VALUES (X, M);",
		"INSERT INTO Customers VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"INSERT INTO dbo.Points (PointValue) VALUES ('1,99');",
		"INSERT INTO dbo.Points (Type, PointValue) VALUES ('Point', '1,5');",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'Seattle'",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE NAME1 = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY1 = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL AS EMPL_TBL WHERE CITY2 = 'Seattle' ORDER BY EMP_ID;",
		"select songName from t where personName in ('Ryan', 'Holly') group by songName having count(distinct personName) = 10",
		"SELECT SUM(Salary) FROM Employee WHERE Emp_Age < 30;",
		"SELECT AVG(Price) FROM Products;",
		"SELECT A, B",
		"SELECT A",
		"SELECT 1",
	}

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	whitelist := handlers.NewAllowHandler(sqlparser.New(sqlparser.ModeStrict))
	censor.AddHandler(whitelist)
	censor.AddHandler(handlers.NewDenyallHandler())

	pattern := "%%SELECT%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}

	for i, query := range testQueries {
		err := censor.HandleQuery(query)
		if !strings.HasPrefix(strings.ToLower(query), "select") {
			if err != common.ErrDenyAllError {
				t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", testQueries[i])
			}
		} else {
			if err != nil {
				t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", testQueries[i])
			}
		}
	}
}
func TestAllowColumnsPattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	whitelist := handlers.NewAllowHandler(sqlparser.New(sqlparser.ModeStrict))
	censor.AddHandler(whitelist)
	censor.AddHandler(handlers.NewDenyallHandler())

	pattern := "SELECT %%COLUMN%%, %%COLUMN%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries := []string{
		"SELECT A, B",
		"SELECT 1, GETDATE()",
		"SELECT 1, (select a from t inner join b on b.id=t.id where b=1)",
	}
	blockableQueries := []string{
		"SELECT A",
		"SELECT A, B, C",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyAllError {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}

	whitelist.Reset()
	pattern = "SELECT A, %%COLUMN%% FROM testTable"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries = []string{
		"SELECT A, B FROM testTable",
		"SELECT A, 2 FROM testTable",
		"SELECT A, GETDATE() FROM testTable",
	}
	blockableQueries = []string{
		"SELECT A FROM testTable",
		"SELECT B, A FROM testTable",
		"SELECT A, B, C FROM testTable",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyAllError {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}

	whitelist.Reset()
	pattern = "SELECT %%COLUMN%%, B FROM testTable"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries = []string{
		"SELECT A, B FROM testTable",
		"SELECT 2, B FROM testTable",
		"SELECT GETDATE(), B FROM testTable",
	}
	blockableQueries = []string{
		"SELECT A FROM testTable",
		"SELECT B, A FROM testTable",
		"SELECT A, B, C FROM testTable",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyAllError {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}

	whitelist.Reset()
	pattern = "SELECT * FROM testTable ORDER BY %%COLUMN%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries = []string{
		"SELECT * FROM testTable ORDER BY Date()",
		"SELECT * FROM testTable ORDER BY 1",
		"SELECT * FROM testTable ORDER BY testColumn",
		"SELECT * FROM testTable ORDER BY (case when f1 then 1 when f1 is null then 2 else 3 end)",
	}
	blockableQueries = []string{
		// defferent ordering
		"SELECT * FROM testTable ORDER BY Date() DESC",
		// different table
		"SELECT * FROM testTable1 ORDER BY 1",
		// different columns in select expressions
		//"SELECT A FROM testTable ORDER BY (case when f1 then 1 when f1 is null then 2 else 3 end)",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyAllError {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}

	// test GroupBy
	whitelist.Reset()
	pattern = "SELECT * FROM testTable GROUP BY %%COLUMN%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries = []string{
		"SELECT * FROM testTable GROUP BY Date()",
		"SELECT * FROM testTable GROUP BY 1",
		"SELECT * FROM testTable GROUP BY testColumn",
		"SELECT * FROM testTable GROUP BY (case when f1 then 1 when f1 is null then 2 else 3 end)",
	}
	blockableQueries = []string{
		// two columns
		"SELECT * FROM testTable GROUP BY column1, column2",
		// ORDER BY presents
		"SELECT * FROM testTable GROUP BY column1 ORDER BY 1",
		// different table
		"SELECT * FROM testTable1 GROUP BY 1",
		// different columns in select expressions
		//"SELECT A FROM testTable GROUP BY (case when f1 then 1 when f1 is null then 2 else 3 end)",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyAllError {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}

	// test GroupBy with Having
	whitelist.Reset()
	pattern = "SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(%%COLUMN%%) > %%VALUE%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}

	blockableQueries = []string{
		// 2 columns inside FuncExpr
		"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a1, a2) > 1000",
		// wrong FuncExpr name
		"SELECT a1 FROM table1 GROUP BY a2 HAVING MIN(a1) > 1000",
		// wrong ComparisonExpr inside Having
		"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a10) < 1000",
		// wrong column in GroupBy
		"SELECT a1 FROM table1 GROUP BY a4 HAVING COUNT(a3) > 0",
		// star in SelectExprs
		"SELECT * FROM table1 GROUP BY a2 HAVING COUNT(a3) > 0",
	}

	acceptableQueries = []string{
		"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a3) > 0",
		"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a2) > 1000",
		"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a1) > TRUE",
	}

	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyAllError {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}
}
func TestAllowWherePattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	whitelist := handlers.NewAllowHandler(sqlparser.New(sqlparser.ModeStrict))
	censor.AddHandler(whitelist)
	censor.AddHandler(handlers.NewDenyallHandler())

	pattern := "SELECT a, b, c FROM z %%WHERE%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries := []string{
		"SELECT a, b, c FROM z WHERE a = 'someValue'",
		"SELECT a, b, c FROM z WHERE a = b",
		"SELECT a, b, c FROM z WHERE a = 'someValue' and b = 2 or c between 20 and 30",
		"SELECT a, b, c FROM z WHERE AGE BETWEEN 25 AND 65000",
		"SELECT a, b, c FROM z WHERE NAME LIKE 'Pa%'",
		"SELECT a, b, c FROM z WHERE AGE IN ( 25, 27 )",
		"SELECT a, b, c FROM z WHERE AGE NOT IN ( 25, 27 )",
		"SELECT a, b, c FROM z WHERE AGE IS NULL",
		"SELECT a, b, c FROM z WHERE AGE > (SELECT AGE FROM company10 WHERE SALARY > 65000)",
		"SELECT a, b, c FROM z WHERE EXISTS (SELECT AGE FROM company11 WHERE SALARY > 65000)",
		"SELECT a, b, c FROM z WHERE A=(SELECT AGE FROM company WHERE SALARY > 65000 limit 1) and B=(SELECT AGE FROM company123 WHERE SALARY > 65000 limit 1)",
	}
	blockableQueries := []string{
		"SELECT a, b, c FROM x WHERE a = 'someValue'",
		"SELECT a, b FROM z WHERE a = 'someValue'",
		"SELECT a, b, c FROM x WHERE a = 'someValue' and b = 48 or c between 10 and 50",
		"SELECT age, age1 FROM company3 WHERE AGE IS NOT NULL",
		"SELECT age, age1 FROM company4 WHERE AGE IS NULL",
		"SELECT age1, age2, age3 FROM company5 WHERE AGE >= 25",
		"SELECT a, b, c FROM company6 WHERE AGE BETWEEN 25 AND 65000",
		"SELECT x, y, z FROM company7 WHERE NAME LIKE 'Pa%'",
		"SELECT betta, gamma FROM company8 WHERE AGE IN ( 25, 27 )",
		"SELECT name, lastname FROM company9 WHERE AGE NOT IN ( 25, 27 )",
		"SELECT a, b FROM company10 WHERE AGE > (SELECT AGE FROM company10 WHERE SALARY > 65000)",
		"SELECT age FROM company11 WHERE EXISTS (SELECT AGE FROM company WHERE SALARY > 65000)",
		"SELECT age FROM company11 WHERE A=(SELECT AGE FROM company WHERE SALARY > 65000 limit 1) and B=(SELECT AGE FROM company123 WHERE SALARY > 65000 limit 1)",
		"SELECT lastname FROM another_table INNER JOIN (SELECT age FROM company WHERE id = 1) AS t ON t.id=another_table.id WHERE AGE NOT IN (25, 27)",
		"SELECT a, b, c FROM z INNER JOIN (SELECT age FROM company WHERE id = 1) AS t ON t.id=another_table.id WHERE AGE NOT IN (25, 27)",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyAllError {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}
}
func TestAllowValuePattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	whitelist := handlers.NewAllowHandler(sqlparser.New(sqlparser.ModeStrict))
	censor.AddHandler(whitelist)
	censor.AddHandler(handlers.NewDenyallHandler())

	pattern := "SELECT a, b from t where ID = %%VALUE%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}

	acceptableQueries := []string{
		// string
		"SELECT a, b FROM t WHERE ID = 'someValue_testValue_1234567890'",
		// int
		"SELECT a, b FROM t WHERE ID = 1",
		// null
		"SELECT a, b FROM t WHERE ID = NULL",
		// boolean
		"SELECT a, b FROM t WHERE ID = TRUE",
		// subquery
		//"SELECT a, b FROM t WHERE ID = (select 1)",
		// float
		"SELECT a, b FROM t WHERE ID = 1.0",
		// function
		"SELECT a, b FROM t WHERE ID = Date()",
	}
	blockableQueries := []string{
		// different column name in WHERE
		"SELECT a, b FROM t WHERE NonID = 'someValue'",
		// two conditions in WHERE
		"SELECT a, b FROM t WHERE ID = 'someValue208934278935789' AND B=2",
		// 3 columns in SELECT
		"SELECT a, b, c FROM y WHERE a = 'someValue'",
		// different table in FROM
		"SELECT a, b FROM z WHERE a = 'someValue'",
		// TODO unsupported casts (postgresql like)
		// cast
		//"SELECT a, b FROM t WHERE ID = CAST( '123' AS bigint )",
		// cast
		//"SELECT a, b FROM t WHERE ID = '123'::integer",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Unexpected result. \nPattern: ", pattern, "\nQuery: ", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyAllError {
			t.Fatal(err, "Unexpected result. \nPattern: ", pattern, "\nQuery: ", query)
		}
	}

	whitelist.Reset()
	pattern = "SELECT * from t where ID = %%VALUE%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}

	acceptableQueries = []string{
		// string
		"SELECT a, b FROM t WHERE ID = 'someValue_testValue_1234567890'",
		// int
		"SELECT a, b FROM t WHERE ID = 1",
		// null
		"SELECT a, b FROM t WHERE ID = NULL",
		// boolean
		"SELECT a, b FROM t WHERE ID = TRUE",
		// subquery
		//"SELECT a, b FROM t WHERE ID = (select 1)",
		// float
		"SELECT a, b FROM t WHERE ID = 1.0",
		// function
		"SELECT a, b FROM t WHERE ID = Date()",
		// with ALL (*)
		"SELECT * FROM t WHERE ID = NULL",
	}

	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyAllError {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}

	// test delete query
	whitelist.Reset()
	pattern = "delete from t where ID = %%VALUE%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}

	acceptableQueries = []string{
		// string
		"delete FROM t WHERE ID = 'someValue_testValue_1234567890'",
		// int
		"delete FROM t WHERE ID = 1",
		// null
		"delete FROM t WHERE ID = NULL",
		// boolean
		"delete FROM t WHERE ID = TRUE",
		// subquery
		//"delete FROM t WHERE ID = (select 1)",
		// float
		"delete FROM t WHERE ID = 1.0",
		// function
		"delete FROM t WHERE ID = Date()",
		// with ALL (*)
		"delete FROM t WHERE ID = NULL",
	}

	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyAllError {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}

	// test update query
	whitelist.Reset()
	pattern = "update t set a=1 where ID = %%VALUE%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}

	acceptableQueries = []string{
		// string
		"update t set a=1 WHERE ID = 'someValue_testValue_1234567890'",
		// int
		"update t set a=1 WHERE ID = 1",
		// null
		"update t set a=1 WHERE ID = NULL",
		// boolean
		"update t set a=1 WHERE ID = TRUE",
		// subquery
		//"update t set a=1 WHERE ID = (select 1)",
		// float
		"update t set a=1 WHERE ID = 1.0",
		// function
		"update t set a=1 WHERE ID = Date()",
		// with ALL (*)
		"update t set a=1 WHERE ID = NULL",
	}

	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyAllError {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}

	// test limit
	whitelist.Reset()
	pattern = "SELECT * from t where ID > 10 LIMIT %%VALUE%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}

	blockableQueries = []string{
		// OFFSET presents
		"SELECT * from t where ID > 10 LIMIT 100 OFFSET 100",
		// no LIMIT expression
		"SELECT * from t where ID > 10",
		// wrong table
		"SELECT * from t1 where ID > 10 LIMIT 100",
		// wrong WHERE clause
		"SELECT * from t where ID < 10 LIMIT 100",
		// wrong columns
		//"SELECT a,b from t where ID > 10 LIMIT 100",
	}

	acceptableQueries = []string{
		"SELECT * from t where ID > 10 LIMIT 100500",
	}

	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyAllError {
			t.Fatal(err, "Unexpected result. \nPattern:", pattern, "\nQuery:", query)
		}
	}
}
func TestAllowStarPattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	whitelist := handlers.NewAllowHandler(sqlparser.New(sqlparser.ModeStrict))
	censor.AddHandler(whitelist)
	censor.AddHandler(handlers.NewDenyallHandler())

	pattern := "SELECT * from company %%WHERE%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}

	acceptableQueries := []string{
		"SELECT a, b FROM company WHERE ID = 'someValue_testValue_1234567890'",
		"SELECT a, b FROM company WHERE ID = 'someValue'",
		"SELECT * FROM company WHERE AGE IS NOT NULL",
		"SELECT * FROM company WHERE AGE IS NULL",
		"SELECT * FROM company WHERE AGE >= 25",
		"SELECT * FROM company WHERE AGE BETWEEN 25 AND 65000",
		"SELECT * FROM company WHERE NAME LIKE 'Pa%'",
		"SELECT * FROM company WHERE AGE IN ( 25, 27 )",
		"SELECT * FROM company WHERE AGE NOT IN ( 25, 27 )",
		"SELECT * FROM company WHERE AGE > (SELECT AGE FROM company WHERE SALARY > 65000)",
		"SELECT age FROM company WHERE EXISTS (SELECT age FROM company WHERE SALARY > 65000)",
	}
	blockableQueries := []string{
		"SELECT * FROM testTable WHERE someParameter = 'someValue208934278935789'",
		"SELECT a, b, c FROM x WHERE a = 'someValue'",
		"SELECT * FROM z WHERE a = 'someValue'",
		"SELECT a, b FROM t WHERE NonID = 'someValue'",
		"SELECT a, b FROM company1 WHERE ID = 'someValue_testValue_1234567890'",
		"SELECT a, b FROM company2 WHERE ID = 'someValue'",
		"SELECT * FROM company3 WHERE AGE IS NOT NULL",
		"SELECT * FROM company4 WHERE AGE IS NULL",
		"SELECT * FROM company5 WHERE AGE >= 25",
		"SELECT * FROM company6 WHERE AGE BETWEEN 25 AND 65000",
		"SELECT * FROM company7 WHERE NAME LIKE 'Pa%'",
		"SELECT * FROM company8 WHERE AGE IN ( 25, 27 )",
		"SELECT * FROM company9 WHERE AGE NOT IN ( 25, 27 )",
		"SELECT * FROM company10 WHERE AGE > (SELECT AGE FROM company10 WHERE SALARY > 65000)",
		"SELECT age FROM company11 WHERE EXISTS (SELECT AGE FROM company11 WHERE SALARY > 65000)",
		"SELECT age FROM company11 WHERE EXISTS (SELECT AGE FROM company WHERE SALARY > 65000)",
		"SELECT age FROM company11 WHERE A=(SELECT AGE FROM company WHERE SALARY > 65000 limit 1) and B=(SELECT AGE FROM company123 WHERE SALARY > 65000 limit 1)",
		"SELECT * FROM another_table INNER JOIN (SELECT * FROM company WHERE id = 1) AS t ON t.id=another_table.id WHERE AGE NOT IN (25, 27)",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Unexpected result. \nPattern: ", pattern, "\nQuery: ", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyAllError {
			t.Fatal(err, "Unexpected result. \nPattern: ", pattern, "\nQuery: ", query)
		}
	}
}
func TestDenyQueries(t *testing.T) {
	var err error
	sqlSelectQueries := []string{
		"SELECT Student_ID FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT EMP_ID, NAME FROM EMPLOYEE_TBL WHERE EMP_ID = '0000';",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"SELECT Name, Age FROM Patients WHERE Age > 40 GROUP BY Age ORDER BY Name;",
		"SELECT COUNT(CustomerID), Country FROM Customers GROUP BY Country;",
		"SELECT SUM(Salary) FROM Employee WHERE Emp_Age < 30;",
	}
	sqlInsertQueries := []string{
		"INSERT SalesStaff1 VALUES (2, 'Michael', 'Blythe'), (3, 'Linda', 'Mitchell'),(4, 'Jillian', 'Carson'), (5, 'Garrett', 'Vargas');",
		"INSERT INTO SalesStaff2 (StaffGUID, FirstName, LastName) VALUES (NEWID(), 'Stephen', 'Jiang');",
		"INSERT INTO Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"INSERT SalesStaff1 VALUES (2, 'Michael', 'Blythe'), (3, 'Linda', 'Mitchell'),(4, 'Jillian', 'Carson'), (5, 'Garrett', 'Vargas');",
		"INSERT INTO SalesStaff2 (StaffGUID, FirstName, LastName) VALUES (NEWID(), 'Stephen', 'Jiang');",
		"INSERT INTO Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"INSERT INTO films VALUES ('UA502', 'Bananas', 105, '1971-07-13', 'Comedy', '82 minutes');",
		"INSERT INTO films (code, title, did, date_prod, kind) VALUES ('B6717', 'Tampopo', 110, '1985-02-10', 'Comedy'), ('HG120', 'The Dinner Game', 140, DEFAULT, 'Comedy');",
		"INSERT INTO films SELECT * FROM tmp_films WHERE date_prod < '2004-05-07';",
	}
	blackList := []string{
		"INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');",
		"SELECT AVG(Price) FROM Products;",
	}
	blacklist := handlers.NewDenyHandler(sqlparser.New(sqlparser.ModeStrict))
	blacklist.AddQueries(blackList)
	acraCensor := NewAcraCensor()
	defer acraCensor.ReleaseAll()
	//set our acracensor to use blacklist for query evaluating
	acraCensor.AddHandler(blacklist)
	//acracensor should not block those queries
	for _, query := range sqlSelectQueries {
		err = acraCensor.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, query := range sqlInsertQueries {
		err = acraCensor.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	testQuery := "insert INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');"
	blacklist.AddQueries([]string{testQuery})
	err = acraCensor.HandleQuery(testQuery)
	//acracensor should block this query because it's in blacklist
	if err != common.ErrDenyByQueryError {
		t.Fatal(err)
	}
	acraCensor.RemoveHandler(blacklist)
	err = acraCensor.HandleQuery(testQuery)
	//acracensor should not block this query because we removed blacklist handler, err should be nil
	if err != nil {
		t.Fatal(err)
	}
	//again set our acracensor to use blacklist for query evaluating
	acraCensor.AddHandler(blacklist)
	err = acraCensor.HandleQuery(testQuery)
	//now acracensor should block testQuery because it's in blacklist
	if err != common.ErrDenyByQueryError {
		t.Fatal(err)
	}
	blacklist.RemoveQueries([]string{testQuery})
	err = acraCensor.HandleQuery(testQuery)
	//now acracensor should not block testQuery
	if err != nil {
		t.Fatal(err)
	}
}
func TestDenyTables(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	blacklist := handlers.NewDenyHandler(sqlparser.New(sqlparser.ModeStrict))
	censor.AddHandler(blacklist)

	testQueries := []string{
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"INSERT INTO Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL AS EMPL_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
	}
	blacklist.AddTables([]string{"EMPLOYEE_TBL", "Customers"})
	//acracensor should block these queries
	queryIndexesToBlock := []int{0, 2, 4, 5, 6}
	for _, i := range queryIndexesToBlock {
		err = censor.HandleQuery(testQueries[i])
		if err != common.ErrDenyByTableError {
			t.Fatal(err)
		}
	}
	//acracensor should not block these queries
	queryIndexesToPass := []int{1, 3}
	for _, i := range queryIndexesToPass {
		err = censor.HandleQuery(testQueries[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	blacklist.RemoveTables([]string{"EMPLOYEE_TBL"})
	err = censor.HandleQuery(testQueries[0])
	//acracensor should not block this query
	if err != nil {
		t.Fatal(err)
	}
	err = censor.HandleQuery(testQueries[2])
	//acracensor should not block this query
	if err != nil {
		t.Fatal(err)
	}
}
func TestDenySelectPattern(t *testing.T) {
	var err error
	testQueries := []string{
		"INSERT SalesStaff1 VALUES (2, 'Michael', 'Blythe'), (3, 'Linda', 'Mitchell'),(4, 'Jillian', 'Carson'), (5, 'Garrett', 'Vargas');",
		"INSERT INTO SalesStaff2 (StaffGUID, FirstName, LastName) VALUES (NEWID(), 'Stephen', 'Jiang');",
		"INSERT INTO SalesStaff3 (StaffID, FullNameTbl) VALUES (X, M);",
		"INSERT INTO Customers VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"INSERT INTO dbo.Points (PointValue) VALUES ('1,99');",
		"INSERT INTO dbo.Points (Type, PointValue) VALUES ('Point', '1,5');",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'Seattle'",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE NAME1 = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY1 = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL AS EMPL_TBL WHERE CITY2 = 'Seattle' ORDER BY EMP_ID;",
		"select songName from t where personName in ('Ryan', 'Holly') group by songName having count(distinct personName) = 10",
		"SELECT SUM(Salary) FROM Employee WHERE Emp_Age < 30;",
		"SELECT AVG(Price) FROM Products;",
		"SELECT A, B",
		"SELECT A",
		"SELECT 1",
	}
	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	blacklist := handlers.NewDenyHandler(sqlparser.New(sqlparser.ModeStrict))
	censor.AddHandler(blacklist)

	blacklistPattern := "%%SELECT%%"
	err = blacklist.AddPatterns([]string{blacklistPattern})
	if err != nil {
		t.Fatal(err)
	}
	//Queries that should be blocked by specified pattern have indexes: [0 .. 12] (all select queries)
	for i, query := range testQueries {
		err = censor.HandleQuery(query)
		if strings.HasPrefix(strings.ToLower(query), "select") {
			if err != common.ErrDenyByPatternError {
				t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern+"\nQuery:", testQueries[i])
			}
		} else {
			if err != nil {
				t.Fatal(err, "\nPattern"+blacklistPattern, "\nQuery"+testQueries[i])
			}
		}
	}
}
func TestDenyColumnsPattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	blacklist := handlers.NewDenyHandler(sqlparser.New(sqlparser.ModeStrict))
	censor.AddHandler(blacklist)

	blacklistPattern := "SELECT %%COLUMN%%, %%COLUMN%%"
	err = blacklist.AddPatterns([]string{blacklistPattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries := []string{
		"SELECT A",
		"SELECT A, B, C",
		"SELECT A, B, C, D",
	}
	blockableQueries := []string{
		"SELECT A, B",
		"SELECT X1, X2",
		"SELECT col1, col2",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Blacklist pattern blocked query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyByPatternError {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}

	blacklist.Reset()
	blacklistPattern = "SELECT A, %%COLUMN%% FROM testTable"
	err = blacklist.AddPatterns([]string{blacklistPattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries = []string{
		"SELECT A FROM testTable",
		"SELECT B, A FROM testTable",
		"SELECT A, B, C FROM testTable",
		"SELECT A, B, C, D FROM testTable",
	}
	blockableQueries = []string{
		"SELECT A, B FROM testTable",
		"SELECT A, X2 FROM testTable",
		"SELECT A, col2 FROM testTable",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Blacklist pattern blocked query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyByPatternError {
			t.Fatal("Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}

	blacklist.Reset()
	blacklistPattern = "SELECT %%COLUMN%%, B FROM testTable"
	err = blacklist.AddPatterns([]string{blacklistPattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries = []string{
		"SELECT A FROM testTable",
		"SELECT B, A FROM testTable",
		"SELECT A, B, C FROM testTable",
		"SELECT A, B, C, D FROM testTable",
	}
	blockableQueries = []string{
		"SELECT A, B FROM testTable",
		"SELECT X2, B FROM testTable",
		"SELECT col2, B FROM testTable",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Blacklist pattern blocked query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyByPatternError {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}

	blacklist.Reset()
	blacklistPattern = "SELECT * FROM testTable ORDER BY %%COLUMN%%"
	err = blacklist.AddPatterns([]string{blacklistPattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries = []string{
		// defferent ordering
		"SELECT * FROM testTable ORDER BY Date() DESC",
		// different table
		"SELECT * FROM testTable1 ORDER BY 1",
		// different columns in select expressions
		//"SELECT A FROM testTable ORDER BY (case when f1 then 1 when f1 is null then 2 else 3 end)",
	}

	blockableQueries = []string{
		"SELECT * FROM testTable ORDER BY Date()",
		"SELECT * FROM testTable ORDER BY 1",
		"SELECT * FROM testTable ORDER BY testColumn",
		"SELECT * FROM testTable ORDER BY (case when f1 then 1 when f1 is null then 2 else 3 end)",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Blacklist pattern blocked query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyByPatternError {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}

	// test GroupBy
	blacklist.Reset()
	blacklistPattern = "SELECT * FROM testTable GROUP BY %%COLUMN%%"
	err = blacklist.AddPatterns([]string{blacklistPattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries = []string{
		// two columns
		"SELECT * FROM testTable GROUP BY column1, column2",
		// ORDER BY presents
		"SELECT * FROM testTable GROUP BY column1 ORDER BY 1",
		// different table
		"SELECT * FROM testTable1 GROUP BY 1",
		// different columns in select expressions
		//"SELECT A FROM testTable GROUP BY (case when f1 then 1 when f1 is null then 2 else 3 end)",
	}
	blockableQueries = []string{
		"SELECT * FROM testTable GROUP BY Date()",
		"SELECT * FROM testTable GROUP BY 1",
		"SELECT * FROM testTable GROUP BY testColumn",
		"SELECT * FROM testTable GROUP BY (case when f1 then 1 when f1 is null then 2 else 3 end)",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Blacklist pattern blocked query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyByPatternError {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}

	// test GroupBy with Having
	blacklist.Reset()
	blacklistPattern = "SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(%%COLUMN%%) > %%VALUE%%"
	err = blacklist.AddPatterns([]string{blacklistPattern})
	if err != nil {
		t.Fatal(err)
	}

	acceptableQueries = []string{
		// 2 columns inside FuncExpr
		"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a1, a2) > 1000",
		// wrong FuncExpr name
		"SELECT a1 FROM table1 GROUP BY a2 HAVING MIN(a1) > 1000",
		// wrong ComparisonExpr inside Having
		"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a10) < 1000",
		// wrong column in GroupBy
		"SELECT a1 FROM table1 GROUP BY a4 HAVING COUNT(a3) > 0",
		// star in SelectExprs
		"SELECT * FROM table1 GROUP BY a2 HAVING COUNT(a3) > 0",
	}

	blockableQueries = []string{
		"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a3) > 0",
		"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a2) > 1000",
		//"SELECT a1 FROM table1 GROUP BY a2 HAVING COUNT(a1) > (select 1)",
	}

	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Blacklist pattern blocked query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyByPatternError {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
}
func TestDenyWherePattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	blacklist := handlers.NewDenyHandler(sqlparser.New(sqlparser.ModeStrict))
	censor.AddHandler(blacklist)

	blacklistPattern := "SELECT a, b, c FROM z %%WHERE%%"
	err = blacklist.AddPatterns([]string{blacklistPattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries := []string{
		"SELECT a, b, c FROM x WHERE a = 'someValue'",
		"SELECT a, b, c FROM y WHERE a = 'someValue'",
		"SELECT a, b FROM z WHERE a = 'someValue'",
		"SELECT a, b, c FROM x WHERE a = 'someValue' and b = 48 or c between 10 and 50",
		"SELECT age, age1 FROM company3 WHERE AGE IS NOT NULL",
		"SELECT age, age1 FROM company4 WHERE AGE IS NULL",
		"SELECT age1, age2, age3 FROM company5 WHERE AGE >= 25",
		"SELECT a, b, c FROM company6 WHERE AGE BETWEEN 25 AND 65000",
		"SELECT x, y, z FROM z WHERE NAME LIKE 'Pa%'",
		"SELECT betta, gamma FROM company8 WHERE AGE IN ( 25, 27 )",
		"SELECT name, lastname FROM company9 WHERE AGE NOT IN ( 25, 27 )",
		"SELECT a, b FROM z WHERE AGE > (SELECT AGE FROM company10 WHERE SALARY > 65000)",
		"SELECT age FROM z WHERE EXISTS (SELECT AGE FROM company11 WHERE SALARY > 65000)",
		"SELECT age FROM company11 WHERE EXISTS (SELECT AGE FROM company WHERE SALARY > 65000)",
		"SELECT age FROM company11 WHERE A=(SELECT AGE FROM company WHERE SALARY > 65000 limit 1) and B=(SELECT AGE FROM company123 WHERE SALARY > 65000 limit 1)",
		"SELECT lastname FROM another_table INNER JOIN (SELECT age FROM company WHERE id = 1) AS t ON t.id=another_table.id WHERE AGE NOT IN (25, 27)",
		"SELECT a, b, c FROM z INNER JOIN (SELECT age FROM company WHERE id = 1) AS t ON t.id=another_table.id WHERE AGE NOT IN (25, 27)",
	}
	blockableQueries := []string{
		"SELECT a, b, c FROM z WHERE a = 'someValue'",
		"SELECT a, b, c FROM z WHERE a = b",
		"SELECT a, b, c FROM z WHERE a < b",
		"SELECT a, b, c FROM z WHERE a = 'someValue' and b = 2 or c between 20 and 30",
		"SELECT a, b, c FROM z WHERE AGE BETWEEN 25 AND 65000",
		"SELECT a, b, c FROM z WHERE NAME LIKE 'Pa%'",
		"SELECT a, b, c FROM z WHERE AGE IN ( 25, 27 )",
		"SELECT a, b, c FROM z WHERE AGE NOT IN ( 25, 27 )",
		"SELECT a, b, c FROM z WHERE AGE > (SELECT AGE FROM company10 WHERE SALARY > 65000)",
		"SELECT a, b, c FROM z WHERE EXISTS (SELECT AGE FROM company11 WHERE SALARY > 65000)",
		"SELECT a, b, c FROM z WHERE EXISTS (SELECT AGE FROM company WHERE SALARY > 65000)",
		"SELECT a, b, c FROM z WHERE A=(SELECT AGE FROM company WHERE SALARY > 65000 limit 1) and B=(SELECT AGE FROM company123 WHERE SALARY > 65000 limit 1)",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Blacklist pattern blocked query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyByPatternError {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
}
func TestDenyValuePattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	blacklist := handlers.NewDenyHandler(sqlparser.New(sqlparser.ModeStrict))
	censor.AddHandler(blacklist)

	blacklistPattern := "SELECT a, b from t where ID = %%VALUE%%"
	err = blacklist.AddPatterns([]string{blacklistPattern})
	if err != nil {
		t.Fatal(err)
	}

	acceptableQueries := []string{
		"SELECT a, b FROM t WHERE someParameter = 'someValue208934278935789'",
		"SELECT a, b, c FROM y WHERE a = 'someValue'",
		"SELECT a, b FROM z WHERE a = 'someValue'",
		"SELECT a, b FROM t WHERE NonID = 'someValue'",
		"SELECT a, b, c, d FROM t WHERE a = 1 OR b = 1.0 OR c = TRUE OR d = NULL",
		"SELECT a, b FROM t WHERE a = 1 and b = 2.0",
	}
	blockableQueries := []string{
		"SELECT a, b FROM t WHERE ID = 'someValue_testValue_1234567890'",
		"SELECT a, b FROM t WHERE ID = 'someValue'",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Blacklist pattern blocked query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyByPatternError {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}

	blacklist.Reset()
	blacklistPattern = "SELECT * from t where ID = %%VALUE%%"
	err = blacklist.AddPatterns([]string{blacklistPattern})
	if err != nil {
		t.Fatal(err)
	}

	blockableQueries = []string{
		"SELECT a, b FROM t WHERE ID = 1",
		"SELECT a, b FROM t WHERE ID = 1.0",
		"SELECT a, b, c, d FROM t WHERE ID = 'someValue'",
		"SELECT a, b, c FROM t WHERE ID = TRUE",
	}

	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Blacklist pattern blocked query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyByPatternError {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}

	// test limit
	blacklist.Reset()
	blacklistPattern = "SELECT * from t where ID > 10 LIMIT %%VALUE%%"
	err = blacklist.AddPatterns([]string{blacklistPattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries = []string{
		// OFFSET presents
		"SELECT * from t where ID > 10 LIMIT 100 OFFSET 100",
		// no LIMIT expression
		"SELECT * from t where ID > 10",
		// wrong table
		"SELECT * from t1 where ID > 10 LIMIT 100",
		// wrong WHERE clause
		"SELECT * from t where ID < 10 LIMIT 100",
		// wrong columns
		//"SELECT a,b from t where ID > 10 LIMIT 100",
	}

	blockableQueries = []string{
		"SELECT * from t where ID > 10 LIMIT 100500",
	}

	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Blacklist pattern blocked query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyByPatternError {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
}
func TestDenyStarPattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	blacklist := handlers.NewDenyHandler(sqlparser.New(sqlparser.ModeStrict))
	censor.AddHandler(blacklist)

	blacklistPattern := "SELECT * from company %%WHERE%%"
	err = blacklist.AddPatterns([]string{blacklistPattern})
	if err != nil {
		t.Fatal(err)
	}

	acceptableQueries := []string{
		"SELECT * FROM testTable WHERE someParameter = 'someValue208934278935789'",
		"SELECT a, b, c FROM x WHERE a = 'someValue'",
		"SELECT * FROM z WHERE a = 'someValue'",
		"SELECT a, b FROM t WHERE NonID = 'someValue'",
		"SELECT a, b FROM company1 WHERE ID = 'someValue_testValue_1234567890'",
		"SELECT a, b FROM company2 WHERE ID = 'someValue'",
		"SELECT * FROM company3 WHERE AGE IS NOT NULL",
		"SELECT * FROM company4 WHERE AGE IS NULL",
		"SELECT * FROM company5 WHERE AGE >= 25",
		"SELECT * FROM company6 WHERE AGE BETWEEN 25 AND 65000",
		"SELECT * FROM company7 WHERE NAME LIKE 'Pa%'",
		"SELECT * FROM company8 WHERE AGE IN ( 25, 27 )",
		"SELECT * FROM company9 WHERE AGE NOT IN ( 25, 27 )",
		"SELECT * FROM company10 WHERE AGE > (SELECT AGE FROM company10 WHERE SALARY > 65000)",
		"SELECT age FROM company11 WHERE EXISTS (SELECT AGE FROM company11 WHERE SALARY > 65000)",
		"SELECT age FROM company11 WHERE EXISTS (SELECT AGE FROM company WHERE SALARY > 65000)",
		"SELECT age FROM company11 WHERE A=(SELECT AGE FROM company WHERE SALARY > 65000 limit 1) and B=(SELECT AGE FROM company123 WHERE SALARY > 65000 limit 1)",
		"SELECT * FROM another_table INNER JOIN (SELECT * FROM company WHERE id = 1) AS t ON t.id=another_table.id WHERE AGE NOT IN (25, 27)",
	}
	blockableQueries := []string{
		"SELECT a, b FROM company WHERE ID = 'someValue_testValue_1234567890'",
		"SELECT a, b FROM company WHERE ID = 'someValue'",
		"SELECT * FROM company WHERE AGE IS NOT NULL",
		"SELECT * FROM company WHERE AGE IS NULL",
		"SELECT * FROM company WHERE AGE >= 25",
		"SELECT * FROM company WHERE AGE BETWEEN 25 AND 65000",
		"SELECT * FROM company WHERE NAME LIKE 'Pa%'",
		"SELECT * FROM company WHERE AGE IN ( 25, 27 )",
		"SELECT * FROM company WHERE AGE NOT IN ( 25, 27 )",
		"SELECT * FROM company WHERE AGE > (SELECT AGE FROM company WHERE SALARY > 65000)",
		"SELECT age FROM company WHERE EXISTS (SELECT age FROM company WHERE SALARY > 65000)",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != common.ErrDenyByPatternError {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
}
func TestAddingCapturedQueriesIntoBlacklist(t *testing.T) {
	// Currently we support adding only non-redacted queries
	testQueries := []string{
		"SELECT Student_ID FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"select * FROM X;",
		"SELECT * FROM Y;",
	}
	tmpFile, err := ioutil.TempFile("", "censor_log")
	if err != nil {
		t.Fatal(err)
	}
	if err = tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	parser := sqlparser.New(sqlparser.ModeStrict)
	queryCaptureHandler, err := handlers.NewQueryCaptureHandler(tmpFile.Name(), parser)
	if err != nil {
		t.Fatal(err)
	}
	go queryCaptureHandler.Start()

	blacklist := handlers.NewDenyHandler(parser)
	acraCensor := NewAcraCensor()
	defer func() {
		acraCensor.ReleaseAll()
		err = os.Remove(tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}
	}()

	acraCensor.AddHandler(queryCaptureHandler)
	acraCensor.AddHandler(blacklist)
	for _, testQuery := range testQueries {
		err = acraCensor.HandleQuery(testQuery)
		if err != nil {
			t.Fatal(err)
		}
	}

	// need to wait extra time to be sure that queryCaptureHandler captured all input queries
	time.Sleep(time.Millisecond * 100)

	indexesOfForbiddenQueries := []int{0, 1, 2}
	for _, forbiddenQueryIndex := range indexesOfForbiddenQueries {
		err = queryCaptureHandler.MarkQueryAsForbidden(testQueries[indexesOfForbiddenQueries[forbiddenQueryIndex]])
		if err != nil {
			t.Fatal(err)
		}
	}
	err = queryCaptureHandler.DumpQueries()
	if err != nil {
		t.Fatal(err)
	}

	blacklist.AddQueries(queryCaptureHandler.GetForbiddenQueries())
	for _, forbiddenQueryIndex := range indexesOfForbiddenQueries {
		err = acraCensor.HandleQuery(testQueries[forbiddenQueryIndex])
		if err != common.ErrDenyByQueryError {
			t.Fatal(err)
		}
	}

	//zero, first and second query are forbidden
	for index := 3; index < len(testQueries); index++ {
		err = acraCensor.HandleQuery(testQueries[index])
		if err != nil {
			t.Fatal(err)
		}
	}
}
func TestQueryIgnoring(t *testing.T) {
	var err error
	testQueries := []string{
		"SELECT Student_ID FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT EMP_ID, NAME FROM EMPLOYEE_TBL WHERE EMP_ID = '0000';",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"SELECT Name, Age FROM Patients WHERE Age > 40 GROUP BY Age ORDER BY Name;",
		"SELECT COUNT(CustomerID), Country FROM Customers GROUP BY Country;",
		"SELECT SUM(Salary)FROM Employee WHERE Emp_Age < 30;",
		"SELECT AVG(Price)FROM Products;",
		"INSERT SalesStaff1 VALUES (2, 'Michael', 'Blythe'), (3, 'Linda', 'Mitchell'),(4, 'Jillian', 'Carson'), (5, 'Garrett', 'Vargas');",
		"INSERT INTO SalesStaff2 (StaffGUID, FirstName, LastName) VALUES (NEWID(), 'Stephen', 'Jiang');",
		"INSERT INTO SalesStaff3 (StaffID, FullName) VALUES (X, 'Y');",
		"INSERT INTO SalesStaff3 (StaffID, FullName) VALUES (X, 'Z');",
		"INSERT INTO SalesStaff3 (StaffID, FullNameTbl) VALUES (X, M);",
		"INSERT INTO X.Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"INSERT INTO Production (Name, UnitMeasureCode,	ModifiedDate) VALUES ('Square Yards', 'Y2', GETDATE());",
		"INSERT INTO T1 (Name, UnitMeasureCode,	ModifiedDate) VALUES ('Square Yards', 'Y2', GETDATE());",
		"INSERT INTO dbo.Points (Type, PointValue) VALUES ('Point', '1,5');",
		"INSERT INTO dbo.Points (PointValue) VALUES ('1,99');",
	}

	parser := sqlparser.New(sqlparser.ModeStrict)
	blacklist := handlers.NewDenyHandler(parser)
	blacklist.AddQueries(testQueries)

	ignoreQueryHandler := handlers.NewQueryIgnoreHandler(parser)
	ignoreQueryHandler.AddQueries(testQueries)

	acraCensor := NewAcraCensor()
	defer acraCensor.ReleaseAll()
	acraCensor.AddHandler(ignoreQueryHandler)
	acraCensor.AddHandler(blacklist)
	//should not block
	for _, query := range testQueries {
		err = acraCensor.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}
	ignoreQueryHandler.Reset()
	//should block
	for _, query := range testQueries {
		err = acraCensor.HandleQuery(query)
		if err != common.ErrDenyByQueryError {
			t.Fatal(err)
		}
	}
	testUnparsableQueries := []string{
		"select * from x )))(((unparsable query",
		"qwerty",
		"qwerty_xxx",
	}
	acraCensor.ignoreParseError = true
	ignoreQueryHandler.AddQueries(testUnparsableQueries)
	for _, query := range testUnparsableQueries {
		err = acraCensor.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}
	acraCensor.ignoreParseError = false
	for _, query := range testUnparsableQueries {
		err = acraCensor.HandleQuery(query)
		if err != sqlparser.ErrQuerySyntaxError {
			t.Fatal(err)
		}
	}
}
func TestConfigurationProvider(t *testing.T) {
	var defaultConfigPath = utils.GetConfigPathByName("acra-censor.example")
	filePath, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := ioutil.ReadFile(filepath.Join(filePath, "../", defaultConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(version:\s+?)((\d+\.?){3})`)
	// replace version from example to current
	configuration = []byte(re.ReplaceAllString(string(configuration), fmt.Sprintf("$1 %s", MinimalCensorConfigVersion)))
	acraCensor := NewAcraCensor()
	defer func() {
		acraCensor.ReleaseAll()
		err = os.Remove("censor.log")
		if err != nil {
			t.Fatal(err)
		}
		err = os.Remove("unparsed_queries.log")
		if err != nil {
			t.Fatal(err)
		}
	}()
	err = acraCensor.LoadConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if acraCensor.ignoreParseError {
		t.Fatal("ignore_parse_error must be 'false' as default")
	}
	if len(acraCensor.handlers) != 3 {
		t.Fatal("Unexpected amount of handlers: ", len(acraCensor.handlers))
	}
	testQueries := []string{
		"INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');",
		"SELECT AVG(Price) FROM Products;",
	}
	//acracensor should block those queries
	for _, queryToBlock := range testQueries {
		err = acraCensor.HandleQuery(queryToBlock)
		if err != common.ErrDenyByQueryError {
			t.Fatal(err)
		}
	}
	testQueries = []string{
		"INSERT INTO EMPLOYEE_TBL VALUES (1, 'Stephen', 'Jiang');",
		"SELECT AVG(Price) FROM Customers;",
	}
	//acracensor should block those tables
	for _, queryToBlock := range testQueries {
		err = acraCensor.HandleQuery(queryToBlock)
		if err != common.ErrDenyByTableError {
			t.Fatal(err)
		}
	}
	testQueries = []string{
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		//"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE AS EMPL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
	}
	//acracensor should block those queries by pattern
	for _, queryToBlock := range testQueries {
		err = acraCensor.HandleQuery(queryToBlock)
		if err != common.ErrDenyByPatternError {
			t.Fatal(err)
		}
	}
	testSyntax(t)
}
func testSyntax(t *testing.T) {
	acraCensor := NewAcraCensor()
	defer acraCensor.ReleaseAll()
	configuration := fmt.Sprintf(`version: %s
handlers:
    handler: deny
    qeries:
      - INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');
      - SELECT AVG(Price) FROM Products;`, MinimalCensorConfigVersion)

	err := acraCensor.LoadConfiguration([]byte(configuration))
	if err == nil {
		t.Fatal(err)
	}
	configuration = fmt.Sprintf(`version: %s
handlers:
  - handler: deny
    queries:
      - INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');
      - SELECT AVG(Price) FROM Products;
    tables:
      - EMPLOYEE_TBL
      - Customers
    patterns:
      - SELECT * ROM EMPLOYEE WHERE CITY='Seattle';`, MinimalCensorConfigVersion)

	err = acraCensor.LoadConfiguration([]byte(configuration))
	if err != common.ErrPatternSyntaxError {
		t.Fatal(err)
	}
}
func TestDifferentTablesParsing(t *testing.T) {
	testQuery :=
		"SELECT Orders.OrderID, Customers.CustomerName, Shippers.ShipperName " +
			"FROM ((Orders " +
			"INNER JOIN Customers ON Orders.CustomerID = Customers.CustomerID) " +
			"INNER JOIN Shippers ON Orders.ShipperID = Shippers.ShipperID);"

	parser := sqlparser.New(sqlparser.ModeStrict)
	denyHandler := handlers.NewDenyHandler(parser)
	denyHandler.AddTables([]string{"x", "y"})

	acraCensor := NewAcraCensor()
	defer acraCensor.ReleaseAll()
	//set our acracensor to use denyHandler for query evaluating
	acraCensor.AddHandler(denyHandler)

	err := acraCensor.HandleQuery(testQuery)
	if err != nil {
		t.Fatal(err)
	}
	denyHandler.AddTables([]string{"z", "Shippers"})
	err = acraCensor.HandleQuery(testQuery)
	if err != common.ErrDenyByTableError {
		t.Fatal(err)
	}

	acraCensor.RemoveHandler(denyHandler)

	allowHandler := handlers.NewAllowHandler(parser)
	allowHandler.AddTables([]string{"Orders", "Customers", "NotShippers"})

	//set our acracensor to use allowHandler for query evaluating
	acraCensor.AddHandler(allowHandler)
	acraCensor.AddHandler(handlers.NewDenyallHandler())
	err = acraCensor.HandleQuery(testQuery)
	if err != common.ErrDenyAllError {
		t.Fatal(err)
	}
	allowHandler.AddTables([]string{"Shippers"})
	err = acraCensor.HandleQuery(testQuery)
	if err != nil {
		t.Fatal(err)
	}
}
func TestIgnoringQueryParseErrors(t *testing.T) {
	queriesWithSyntaxErrors := []string{
		"Insert into something",
	}
	acraCensor := NewAcraCensor()
	defer acraCensor.ReleaseAll()

	parser := sqlparser.New(sqlparser.ModeStrict)
	whitelist := handlers.NewAllowHandler(parser)
	whitelist.AddTables([]string{"some table"})
	blacklist := handlers.NewDenyHandler(parser)
	blacklist.AddTables([]string{"some table"})
	checkHandler := func(queryHandlers []QueryHandlerInterface, expectedError error) {
		for _, handler := range queryHandlers {
			acraCensor.AddHandler(handler)
		}
		for _, query := range queriesWithSyntaxErrors {
			err := acraCensor.HandleQuery(query)
			if err != expectedError {
				t.Fatalf("unexpected error value - %v", err)
			}
		}
		for _, handler := range queryHandlers {
			acraCensor.RemoveHandler(handler)
		}
	}
	checkHandler([]QueryHandlerInterface{whitelist}, sqlparser.ErrQuerySyntaxError)
	checkHandler([]QueryHandlerInterface{blacklist}, sqlparser.ErrQuerySyntaxError)
	// check when censor with two handlers and each one will return query parse error
	checkHandler([]QueryHandlerInterface{whitelist, blacklist}, sqlparser.ErrQuerySyntaxError)
	acraCensor.ignoreParseError = true
	checkHandler([]QueryHandlerInterface{whitelist}, nil)
	checkHandler([]QueryHandlerInterface{blacklist}, nil)
	// check when censor with two handlers and each one will return query parse error
	checkHandler([]QueryHandlerInterface{whitelist, blacklist}, nil)
}

func waitQueryProcessing(expectedCount int, writer *common.QueryWriter, t testing.TB) {
	timeout := time.NewTimer(time.Second*5)
	for {
		select {
		case <-timeout.C:
			t.Fatal("Haven't waited expected amount of queries")
		default:
			break
		}
		if len(writer.Queries) == expectedCount{
			return
		}
		// give some time to process channel
		time.Sleep(common.DefaultSerializationTimeout)
	}
}

func TestLogUnparsedQueries(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "censor_log")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			t.Fatal(err)
		}
	}()
	if err = tmpFile.Close(); err != nil {
		t.Fatal(err)
	}
	configuration := fmt.Sprintf(`ignore_parse_error: true
version: %s
parse_errors_log: %s
handlers:
  - handler: deny
    queries:
      - INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');
      - SELECT AVG(Price) FROM Products;
    tables:
      - EMPLOYEE_TBL
      - Customers
    patterns:
      - SELECT EMP_ID, LAST_NAME FROM EMPLOYEE %%%%WHERE%%%%;`, MinimalCensorConfigVersion, tmpFile.Name())

	acraCensor := NewAcraCensor()
	defer func() {
		acraCensor.ReleaseAll()
	}()
	err = acraCensor.LoadConfiguration([]byte(configuration))
	if err != nil {
		t.Fatal(err)
	}
	testQueries := []string{
		"select * from x )))(((unparsable query",
		"qwerty",
		"qwerty_xxx",
	}
	for _, query := range testQueries {
		err = acraCensor.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}
	waitQueryProcessing(len(testQueries), acraCensor.unparsedQueriesWriter, t)
	//wait until goroutine handles complex serialization
	time.Sleep(common.DefaultSerializationTimeout * 2)
	bufferBytes, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	var queries []*common.QueryInfo
	if len(bufferBytes) != 0 {
		for _, line := range bytes.Split(bufferBytes, []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			var oneQuery common.QueryInfo
			if err = json.Unmarshal(line, &oneQuery); err != nil {
				t.Fatal(err)
			}
			queries = append(queries, &oneQuery)
		}
	}
	if len(queries) != len(testQueries) {
		t.Fatal("Not dumped all queries")
	}
	for index, query := range testQueries {
		if !strings.EqualFold(query, queries[index].RawQuery) {
			fmt.Println(queries[index].RawQuery)
			t.Fatal("Scanned: " + queries[index].RawQuery + ", expected: " + query)
		}
	}
}
func TestAllowAllDenyAll(t *testing.T) {
	allowQueries := []string{
		"SELECT Student_ID FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT EMP_ID, NAME FROM EMPLOYEE_TBL WHERE EMP_ID = '0000';",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"SELECT Name, Age FROM Patients WHERE Age > 40 GROUP BY Age ORDER BY Name;",
		"SELECT COUNT(CustomerID), Country FROM Customers GROUP BY Country;",
		"SELECT SUM(Salary) FROM Employee WHERE Emp_Age < 30;",
	}
	allowallHandler := handlers.NewAllowallHandler()
	for _, query := range allowQueries {
		if _, err := allowallHandler.CheckQuery(query, nil); err != nil {
			t.Fatal("Unexpected deny on query: ", query)
		}
	}

	denyQueries := []string{
		"INSERT SalesStaff1 VALUES (2, 'Michael', 'Blythe'), (3, 'Linda', 'Mitchell'),(4, 'Jillian', 'Carson'), (5, 'Garrett', 'Vargas');",
		"INSERT INTO SalesStaff2 (StaffGUID, FirstName, LastName) VALUES (NEWID(), 'Stephen', 'Jiang');",
		"INSERT INTO Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"INSERT SalesStaff1 VALUES (2, 'Michael', 'Blythe'), (3, 'Linda', 'Mitchell'),(4, 'Jillian', 'Carson'), (5, 'Garrett', 'Vargas');",
		"INSERT INTO SalesStaff2 (StaffGUID, FirstName, LastName) VALUES (NEWID(), 'Stephen', 'Jiang');",
		"INSERT INTO Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"INSERT INTO films VALUES ('UA502', 'Bananas', 105, '1971-07-13', 'Comedy', '82 minutes');",
		"INSERT INTO films (code, title, did, date_prod, kind) VALUES ('B6717', 'Tampopo', 110, '1985-02-10', 'Comedy'), ('HG120', 'The Dinner Game', 140, DEFAULT, 'Comedy');",
		"INSERT INTO films SELECT * FROM tmp_films WHERE date_prod < '2004-05-07';",
	}
	denyallHandler := handlers.NewDenyallHandler()
	for _, query := range denyQueries {
		if _, err := denyallHandler.CheckQuery(query, nil); err != common.ErrDenyAllError {
			t.Fatal("Unexpected allow on query: ", query)
		}
	}
}
func TestAllowDenyTables(t *testing.T) {
	configuration := fmt.Sprintf(`version: %s
handlers:
  - handler: allow
    tables:
      - x
      - y
      - z
  - handler: deny
    tables:
      - x1
  - handler: allow
    tables:
      - x2
  - handler: denyall`, MinimalCensorConfigVersion)

	acraCensor := NewAcraCensor()
	defer acraCensor.ReleaseAll()

	err := acraCensor.LoadConfiguration([]byte(configuration))
	if err != nil {
		t.Fatal(err)
	}
	queriesToAllow := []string{
		"select * from x",
		"select * from y",
		"select * from z",
		"select * from x2",
	}
	for _, query := range queriesToAllow {
		err = acraCensor.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}
	queriesToDeny := []string{
		"select * from x1",
	}
	for _, query := range queriesToDeny {
		err = acraCensor.HandleQuery(query)
		if err != common.ErrDenyByTableError {
			t.Fatal(err)
		}
	}
	queriesToDenyAll := []string{
		"select * from x3",
		"select * from anyNotWhitelistedQuery",
	}
	for _, query := range queriesToDenyAll {
		err = acraCensor.HandleQuery(query)
		fmt.Println(err)
		if err != common.ErrDenyAllError {
			t.Fatal(err)
		}
	}
}
