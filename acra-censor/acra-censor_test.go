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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cossacklabs/acra/acra-censor/handlers"
	"github.com/cossacklabs/acra/utils"
)

func TestWhitelistQueries(t *testing.T) {
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
	whitelistHandler := handlers.NewWhitelistHandler()
	whitelistHandler.AddQueries(sqlSelectQueries)
	whitelistHandler.AddQueries(sqlInsertQueries)
	acraCensor := NewAcraCensor()
	defer acraCensor.ReleaseAll()
	//set our acracensor to use whitelist for query evaluating
	acraCensor.AddHandler(whitelistHandler)
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
	err = acraCensor.HandleQuery("SELECT * FROM Schema.views;")
	if err != handlers.ErrQueryNotInWhitelist {
		t.Fatal(err)
	}
	//ditto
	err = acraCensor.HandleQuery("INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');")
	if err != handlers.ErrQueryNotInWhitelist {
		t.Fatal(err)
	}
}
func TestWhitelistTables(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	whitelistHandler := handlers.NewWhitelistHandler()
	censor.AddHandler(whitelistHandler)

	testQueries := []string{
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"INSERT INTO Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL AS EMPL_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
	}
	whitelistHandler.AddQueries(testQueries)
	whitelistHandler.AddTables([]string{"EMPLOYEE"})
	queryIndexesToBlock := []int{0, 2, 3, 4, 5, 6}
	//acracensor should block those queries
	for _, i := range queryIndexesToBlock {
		err := censor.HandleQuery(testQueries[i])
		if err != handlers.ErrAccessToForbiddenTableWhitelist {
			t.Fatal(err)
		}
	}
	err = censor.HandleQuery(testQueries[1])
	//acracensor should not block this query
	if err != nil {
		t.Fatal(err)
	}
	//Now we have no tables in whitelist, so should block all queries
	whitelistHandler.RemoveTables([]string{"EMPLOYEE"})
	//acracensor should not block queries
	for _, query := range testQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}
	testQuery := "SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL, CUSTOMERS WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;"
	whitelistHandler.AddQueries([]string{testQuery})
	whitelistHandler.AddTables([]string{"EMPLOYEE", "EMPLOYEE_TBL"})
	err = censor.HandleQuery(testQuery)
	//acracensor should block this query
	if err != handlers.ErrAccessToForbiddenTableWhitelist {
		t.Fatal(err)
	}
	whitelistHandler.AddTables([]string{"CUSTOMERS"})
	err = censor.HandleQuery(testQuery)
	//acracensor should not block this query
	if err != nil {
		t.Fatal(err)
	}
}
func TestWhitelistPatterns(t *testing.T) {
	//test %%SELECT%% pattern
	testWhitelistSelectPattern(t)
	//test SELECT %%COLUMN%% .. %%COLUMN%% pattern
	testWhitelistColumnsPattern(t)
	//test SELECT a, b from t %%WHERE%% pattern
	testWhitelistWherePattern(t)
	//test SELECT a, b from t where ID = %%VALUE%%
	testWhitelistValuePattern(t)
	//test SELECT * FROM company %%WHERE%%
	testWhitelistStarPattern(t)
}
func testWhitelistSelectPattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	whitelist := handlers.NewWhitelistHandler()
	censor.AddHandler(whitelist)

	queries := []string{
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
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'Seattle'",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE NAME1 = 'Seattle' ORDER BY EMP_ID;",
		"SELECT TEST_COLUMN1 FROM TEST_TABLE WHERE CITY = 'Seattle'",
		"SELECT EMP_ID FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY1 = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL AS EMPL_TBL WHERE CITY2 = 'Seattle' ORDER BY EMP_ID;",
		"select songName from t where personName in ('Ryan', 'Holly') group by songName having count(distinct personName) = 10",
		"SELECT SUM(Salary) FROM Employee WHERE Emp_Age < 30;",
		"SELECT AVG(Price) FROM Products;",
		"SELECT A, B",
		"SELECT X, Y",
		"SELECT A",
		"SELECT Y",
	}
	pattern := "%%SELECT%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}

	const InsertQueryCounter = 11
	//Queries that should be passed by specified pattern have indexes: [0 .. 10] (all insert queries)
	for i, query := range queries {
		err := censor.HandleQuery(query)
		if i < InsertQueryCounter {
			if err != handlers.ErrWhitelistPatternMismatch {
				t.Fatal(err, "Whitelist pattern passed query. \nPattern:", pattern, "\nQuery:", queries[i])
			}
		} else {
			if err != nil {
				t.Fatal(err, "Whitelist pattern blocked query. \nPattern:", pattern, "\nQuery:", queries[i])
			}
		}
	}
}
func testWhitelistColumnsPattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	whitelist := handlers.NewWhitelistHandler()
	censor.AddHandler(whitelist)

	pattern := "SELECT %%COLUMN%%, %%COLUMN%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries := []string{
		"SELECT A, B",
		"SELECT X1, X2",
		"SELECT col1, col2",
	}
	blockableQueries := []string{
		"SELECT A",
		"SELECT A, B, C",
		"SELECT A, B, C, D",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Whitelist pattern blocked query. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != handlers.ErrWhitelistPatternMismatch {
			t.Fatal(err, "Whitelist pattern passed query. \nPattern:", pattern, "\nQuery:", query)
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
		"SELECT A, X2 FROM testTable",
		"SELECT A, col2 FROM testTable",
	}
	blockableQueries = []string{
		"SELECT A FROM testTable",
		"SELECT B, A FROM testTable",
		"SELECT A, B, C FROM testTable",
		"SELECT A, B, C, D FROM testTable",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Whitelist pattern blocked query. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != handlers.ErrWhitelistPatternMismatch {
			t.Fatal(err, "Whitelist pattern passed query. \nPattern:", pattern, "\nQuery:", query)
		}
	}

	pattern = "SELECT %%COLUMN%%, B FROM testTable"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries = []string{
		"SELECT A, B FROM testTable",
		"SELECT X2, B FROM testTable",
		"SELECT col2, B FROM testTable",
	}
	blockableQueries = []string{
		"SELECT A FROM testTable",
		"SELECT B, A FROM testTable",
		"SELECT A, B, C FROM testTable",
		"SELECT A, B, C, D FROM testTable",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Whitelist pattern blocked query. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != handlers.ErrWhitelistPatternMismatch {
			t.Fatal(err, "Whitelist pattern passed query. \nPattern:", pattern, "\nQuery:", query)
		}
	}
}
func testWhitelistWherePattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	whitelist := handlers.NewWhitelistHandler()
	censor.AddHandler(whitelist)

	pattern := "SELECT a, b, c FROM z %%WHERE%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}
	acceptableQueries := []string{
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
	blockableQueries := []string{
		"SELECT a, b, c FROM x WHERE a = 'someValue'",
		"SELECT a, b, c FROM y WHERE a = 'someValue'",
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
		"SELECT age FROM company11 WHERE EXISTS (SELECT AGE FROM company11 WHERE SALARY > 65000)",
		"SELECT age FROM company11 WHERE EXISTS (SELECT AGE FROM company WHERE SALARY > 65000)",
		"SELECT age FROM company11 WHERE A=(SELECT AGE FROM company WHERE SALARY > 65000 limit 1) and B=(SELECT AGE FROM company123 WHERE SALARY > 65000 limit 1)",
		"SELECT lastname FROM another_table INNER JOIN (SELECT age FROM company WHERE id = 1) AS t ON t.id=another_table.id WHERE AGE NOT IN (25, 27)",
		"SELECT a, b, c FROM z INNER JOIN (SELECT age FROM company WHERE id = 1) AS t ON t.id=another_table.id WHERE AGE NOT IN (25, 27)",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Whitelist pattern blocked query. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != handlers.ErrWhitelistPatternMismatch {
			t.Fatal(err, "Whitelist pattern passed query. \nPattern:", pattern, "\nQuery:", query)
		}
	}
}
func testWhitelistValuePattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	whitelist := handlers.NewWhitelistHandler()
	censor.AddHandler(whitelist)

	pattern := "SELECT a, b from t where ID = %%VALUE%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}

	acceptableQueries := []string{
		"SELECT a, b FROM t WHERE ID = 'someValue_testValue_1234567890'",
		"SELECT a, b FROM t WHERE ID = 'someValue'",
	}
	blockableQueries := []string{
		"SELECT a, b FROM t WHERE someParameter = 'someValue208934278935789'",
		"SELECT a, b, c FROM y WHERE a = 'someValue'",
		"SELECT a, b FROM z WHERE a = 'someValue'",
		"SELECT a, b FROM t WHERE NonID = 'someValue'",
		"SELECT a, b, c, d FROM t WHERE a = 1 OR b = 1.0 OR c = TRUE OR d = NULL",
		"SELECT a, b FROM t WHERE a = 1 and b = 2.0",
	}
	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Blacklist pattern blocked query. \nPattern: ", pattern, "\nQuery: ", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != handlers.ErrWhitelistPatternMismatch {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern: ", pattern, "\nQuery: ", query)
		}
	}

	whitelist.Reset()
	pattern = "SELECT * from t where ID = %%VALUE%%"
	err = whitelist.AddPatterns([]string{pattern})
	if err != nil {
		t.Fatal(err)
	}

	acceptableQueries = []string{
		"SELECT a, b FROM t WHERE ID = 'someValue_testValue_1234567890'",
		"SELECT a, b FROM t WHERE ID = 'someValue'",
		"SELECT a, b, c, d FROM t WHERE ID = 'someValue'",
	}

	for _, query := range acceptableQueries {
		err = censor.HandleQuery(query)
		if err != nil {
			t.Fatal(err, "Whitelist pattern blocked query. \nPattern:", pattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != handlers.ErrWhitelistPatternMismatch {
			t.Fatal(err, "Whitelist pattern passed query. \nPattern:", pattern, "\nQuery:", query)
		}
	}
}
func testWhitelistStarPattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	whitelist := handlers.NewWhitelistHandler()
	censor.AddHandler(whitelist)

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
			t.Fatal(err, "Whitelist pattern passed query. \nPattern: ", pattern, "\nQuery: ", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != handlers.ErrWhitelistPatternMismatch {
			t.Fatal(err, "Whitelist pattern passed query. \nPattern: ", pattern, "\nQuery: ", query)
		}
	}
}

func TestBlacklistQueries(t *testing.T) {
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
		"SELECT * FROM Schema.views;",
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
	blacklist := handlers.NewBlacklistHandler()
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
	testQuery := "INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');"
	blacklist.AddQueries([]string{testQuery})
	err = acraCensor.HandleQuery(testQuery)
	//acracensor should block this query because it's in blacklist
	if err != handlers.ErrQueryInBlacklist {
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
	if err != handlers.ErrQueryInBlacklist {
		t.Fatal(err)
	}
	blacklist.RemoveQueries([]string{testQuery})
	err = acraCensor.HandleQuery(testQuery)
	//now acracensor should not block testQuery
	if err != nil {
		t.Fatal(err)
	}
}
func TestBlacklistTables(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	blacklist := handlers.NewBlacklistHandler()
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
		err := censor.HandleQuery(testQueries[i])
		if err != handlers.ErrAccessToForbiddenTableBlacklist {
			t.Fatal(err)
		}
	}
	//acracensor should not block these queries
	queryIndexesToPass := []int{1, 3}
	for _, i := range queryIndexesToPass {
		err := censor.HandleQuery(testQueries[i])
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
func TestBlacklistPatterns(t *testing.T) {
	//test %%SELECT%% pattern
	testBlacklistSelectPattern(t)
	//test SELECT %%COLUMN%% .. %%COLUMN%% pattern
	testBlacklistColumnsPattern(t)
	//test SELECT a, b from t %%WHERE%% pattern
	testBlacklistWherePattern(t)
	//test SELECT a, b from t where ID = %%VALUE%%
	testBlacklistValuePattern(t)
	//test SELECT * FROM company %%WHERE%%
	testBlacklistStarPattern(t)
}
func testBlacklistSelectPattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	blacklist := handlers.NewBlacklistHandler()
	censor.AddHandler(blacklist)

	queries := []string{
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'Seattle'",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE NAME1 = 'Seattle' ORDER BY EMP_ID;",
		"SELECT TEST_COLUMN1 FROM TEST_TABLE WHERE CITY = 'Seattle'",
		"SELECT EMP_ID FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY1 = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL AS EMPL_TBL WHERE CITY2 = 'Seattle' ORDER BY EMP_ID;",
		"select songName from t where personName in ('Ryan', 'Holly') group by songName having count(distinct personName) = 10",
		"SELECT SUM(Salary) FROM Employee WHERE Emp_Age < 30;",
		"SELECT AVG(Price) FROM Products;",
		"SELECT A, B",
		"SELECT X, Y",
		"SELECT A",
		"SELECT Y",
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
	blacklistPattern := "%%SELECT%%"
	err = blacklist.AddPatterns([]string{blacklistPattern})
	if err != nil {
		t.Fatal(err)
	}
	const SelectQueryCount = 13
	//Queries that should be blocked by specified pattern have indexes: [0 .. 12] (all select queries)
	for i, query := range queries {
		err := censor.HandleQuery(query)
		if i < SelectQueryCount {
			if err != handlers.ErrBlacklistPatternMatch {
				t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern+"\nQuery:", queries[i])
			}
		} else {
			if err != nil {
				t.Fatal(err, "\nPattern"+blacklistPattern, "\nQuery"+queries[i])
			}
		}
	}
}
func testBlacklistColumnsPattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	blacklist := handlers.NewBlacklistHandler()
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
		if err != handlers.ErrBlacklistPatternMatch {
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
		if err != handlers.ErrBlacklistPatternMatch {
			t.Fatal("Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}

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
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
	for _, query := range blockableQueries {
		err = censor.HandleQuery(query)
		if err != handlers.ErrBlacklistPatternMatch {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}

}
func testBlacklistWherePattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	blacklist := handlers.NewBlacklistHandler()
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
		if err != handlers.ErrBlacklistPatternMatch {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
}
func testBlacklistValuePattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	blacklist := handlers.NewBlacklistHandler()
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
		if err != handlers.ErrBlacklistPatternMatch {
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
		if err != handlers.ErrBlacklistPatternMatch {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
		}
	}
}
func testBlacklistStarPattern(t *testing.T) {
	var err error

	censor := NewAcraCensor()
	defer censor.ReleaseAll()
	blacklist := handlers.NewBlacklistHandler()
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
		if err != handlers.ErrBlacklistPatternMatch {
			t.Fatal(err, "Blacklist pattern passed query. \nPattern:", blacklistPattern, "\nQuery:", query)
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
	blacklist := handlers.NewBlacklistHandler()
	blacklist.AddQueries(testQueries)

	ignoreQueryHandler := handlers.NewQueryIgnoreHandler()
	ignoreQueryHandler.AddQueries(testQueries)

	acraCensor := NewAcraCensor()
	defer acraCensor.ReleaseAll()
	acraCensor.AddHandler(ignoreQueryHandler)
	acraCensor.AddHandler(blacklist)
	//should not block
	for _, query := range testQueries {
		err := acraCensor.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}
	ignoreQueryHandler.Reset()
	//should block
	for _, query := range testQueries {
		err = acraCensor.HandleQuery(query)
		if err != handlers.ErrQueryInBlacklist {
			t.Fatal(err)
		}
	}
}
func TestSerialization(t *testing.T) {
	testQueries := []string{
		"SELECT Student_ID FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT * FROM X;",
		"SELECT * FROM Y;",
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
	tmpFile, err := ioutil.TempFile("", "censor_log")
	if err != nil {
		t.Fatal(err)
	}
	if err = tmpFile.Close(); err != nil {
		t.Fatal(err)
	}
	handler, err := handlers.NewQueryCaptureHandler(tmpFile.Name())
	defer handler.Release()
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range testQueries {
		_, err = handler.CheckQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}
	defaultTimeout := handler.GetSerializationTimeout()
	handler.SetSerializationTimeout(50 * time.Millisecond)
	//wait until goroutine handles complex serialization
	time.Sleep(defaultTimeout + handler.GetSerializationTimeout() + 10*time.Millisecond)
	if len(handler.GetAllInputQueries()) != len(testQueries) {
		t.Fatal("Expected: " + strings.Join(testQueries, " | ") + "\nGot: " + strings.Join(handler.GetAllInputQueries(), " | "))
	}
	err = handler.DumpAllQueriesToFile()
	if err != nil {
		t.Fatal(err)
	}
	handler.Reset()
	if len(handler.GetAllInputQueries()) != 0 {
		t.Fatal("Expected no queries \nGot: " + strings.Join(handler.GetAllInputQueries(), " | "))
	}
	err = handler.ReadAllQueriesFromFile()
	if err != nil {
		t.Fatal(err)
	}
	if len(handler.GetAllInputQueries()) != len(testQueries) {
		t.Fatal("Expected: " + strings.Join(testQueries, " | ") + "\nGot: " + strings.Join(handler.GetAllInputQueries(), " | "))
	}
	for index, query := range handler.GetAllInputQueries() {
		if strings.EqualFold(testQueries[index], query) {
			t.Fatal("Expected: " + testQueries[index] + "\nGot: " + query)
		}
	}
	if err = os.Remove(tmpFile.Name()); err != nil {
		t.Fatal(err)
	}
}
func TestLogging(t *testing.T) {
	testQueries := []string{
		"SELECT Student_ID FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT * FROM X;",
		"SELECT * FROM Y;",
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
	tmpFile, err := ioutil.TempFile("", "censor_log")
	if err != nil {
		t.Fatal(err)
	}
	if err = tmpFile.Close(); err != nil {
		t.Fatal(err)
	}
	captureHandler, err := handlers.NewQueryCaptureHandler(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	blacklist := handlers.NewBlacklistHandler()
	acraCensor := NewAcraCensor()
	defer acraCensor.ReleaseAll()
	acraCensor.AddHandler(captureHandler)
	acraCensor.AddHandler(blacklist)
	for _, testQuery := range testQueries {
		err = acraCensor.HandleQuery(testQuery)
		if err != nil {
			t.Fatal(err)
		}
	}
	captureHandler.MarkQueryAsForbidden(testQueries[0])
	captureHandler.MarkQueryAsForbidden(testQueries[1])
	captureHandler.MarkQueryAsForbidden(testQueries[2])
	captureHandler.DumpAllQueriesToFile()

	blacklist.AddQueries(captureHandler.GetForbiddenQueries())
	err = acraCensor.HandleQuery(testQueries[0])
	if err != handlers.ErrQueryInBlacklist {
		t.Fatal(err)
	}
	err = acraCensor.HandleQuery(testQueries[1])
	if err != handlers.ErrQueryInBlacklist {
		t.Fatal(err)
	}
	err = acraCensor.HandleQuery(testQueries[2])
	if err != handlers.ErrQueryInBlacklist {
		t.Fatal(err)
	}
	//zero, first and second query are forbidden
	for index := 3; index < len(testQueries); index++ {
		err = acraCensor.HandleQuery(testQueries[index])
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Remove(tmpFile.Name()); err != nil {
		t.Fatal(err)
	}
}
func TestQueryCapture(t *testing.T) {
	// extraWaitTime provide extra time to serialize in background goroutine before check
	const extraWaitTime = 100 * time.Millisecond
	tmpFile, err := ioutil.TempFile("", "censor_log")
	if err != nil {
		t.Fatal(err)
	}
	if err = tmpFile.Close(); err != nil {
		t.Fatal(err)
	}
	handler, err := handlers.NewQueryCaptureHandler(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Release()
	testQueries := []string{
		"SELECT Student_ID FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT * FROM X;",
		"SELECT * FROM Y;",
	}
	for _, query := range testQueries {
		_, err = handler.CheckQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}
	expected := "{\"RawQuery\":\"SELECT Student_ID FROM STUDENT\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM STUDENT\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM X\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM Y\",\"IsForbidden\":false}\n"

	defaultTimeout := handler.GetSerializationTimeout()
	handler.SetSerializationTimeout(50 * time.Millisecond)
	//wait until goroutine handles complex serialization
	time.Sleep(defaultTimeout + handler.GetSerializationTimeout() + extraWaitTime)
	result, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(strings.ToUpper(string(result)), strings.ToUpper(expected)) {
		t.Fatal("Expected: " + expected + "\nGot: " + string(result))
	}
	testQuery := "SELECT * FROM Z;"
	_, err = handler.CheckQuery(testQuery)
	if err != nil {
		t.Fatal(err)
	}
	expected = "{\"RawQuery\":\"SELECT Student_ID FROM STUDENT\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM STUDENT\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM X\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM Y\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM Z\",\"IsForbidden\":false}\n"

	time.Sleep(handler.GetSerializationTimeout() + extraWaitTime)
	result, err = ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(strings.ToUpper(string(result)), strings.ToUpper(expected)) {
		t.Fatal("Expected: " + expected + "\nGot: " + string(result))
	}

	//Check that values are hidden while logging
	testQuery = "select songName from t where personName in ('Ryan', 'Holly') group by songName having count(distinct personName) = 10"

	handler.CheckQuery(testQuery)

	//wait until serialization completes
	time.Sleep(handler.GetSerializationTimeout() + extraWaitTime)

	result, err = ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	expectedPrefix := "{\"RawQuery\":\"SELECT Student_ID FROM STUDENT\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM STUDENT\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM X\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM Y\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM Z\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"select songName from t where personName in"

	suffix := strings.TrimPrefix(strings.ToUpper(string(result)), strings.ToUpper(expectedPrefix))

	//we expect TWO placeholders here: instead of "('Ryan', 'Holly')" and instead of "10"
	if strings.Count(suffix, strings.ToUpper(handlers.ValuePlaceholder)) != 2 {
		t.Fatal("unexpected placeholder values in following: " + string(result))
	}

	if strings.Contains(strings.ToUpper(string(result)), strings.ToUpper("Ryan")) ||
		strings.Contains(strings.ToUpper(string(result)), strings.ToUpper("Holly")) ||
		strings.Contains(strings.ToUpper(string(result)), strings.ToUpper("10")) {
		t.Fatal("values detected in logs: " + string(result))
	}

	if err = os.Remove(tmpFile.Name()); err != nil {
		t.Fatal(err)
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
	acraCensor := NewAcraCensor()
	defer func() {
		acraCensor.ReleaseAll()
		err = os.Remove("censor_log")
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
		if err != handlers.ErrQueryInBlacklist {
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
		if err != handlers.ErrAccessToForbiddenTableBlacklist {
			t.Fatal(err)
		}
	}
	testQueries = []string{
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		//"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE AS EMPL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
	}
	//acracensor should block those structures
	for _, queryToBlock := range testQueries {
		err = acraCensor.HandleQuery(queryToBlock)
		if err != handlers.ErrBlacklistPatternMatch {
			t.Fatal(err)
		}
	}
	for _, currentHandler := range acraCensor.handlers {
		original, ok := currentHandler.(*handlers.QueryCaptureHandler)
		if ok {
			defaultTimeout := original.GetSerializationTimeout()
			original.SetSerializationTimeout(50 * time.Millisecond)
			//wait until goroutine handles complex serialization
			time.Sleep(defaultTimeout + original.GetSerializationTimeout() + 10*time.Millisecond)
		}
	}
	testSyntax(t)
}
func testSyntax(t *testing.T) {
	acraCensor := NewAcraCensor()
	defer acraCensor.ReleaseAll()
	configuration := `handlers:
  	handler: blacklist
    qeries:
      - INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');
      - SELECT AVG(Price) FROM Products;`

	err := acraCensor.LoadConfiguration([]byte(configuration))
	if err == nil {
		t.Fatal(err)
	}
	configuration = `handlers:
  - handler: blacklist
    queries:
      - INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');
      - SELECT AVG(Price) FROM Products;
    tables:
      - EMPLOYEE_TBL
      - Customers
    patterns:
      - SELECT * ROM EMPLOYEE WHERE CITY='Seattle';`

	err = acraCensor.LoadConfiguration([]byte(configuration))
	if err != handlers.ErrPatternSyntaxError {
		t.Fatal(err)
	}
}
func TestDifferentTablesParsing(t *testing.T) {
	testQuery :=
		"SELECT Orders.OrderID, Customers.CustomerName, Shippers.ShipperName " +
			"FROM ((Orders " +
			"INNER JOIN Customers ON Orders.CustomerID = Customers.CustomerID) " +
			"INNER JOIN Shippers ON Orders.ShipperID = Shippers.ShipperID);"

	blacklist := handlers.NewBlacklistHandler()
	blacklist.AddTables([]string{"x", "y"})
	_, err := blacklist.CheckQuery(testQuery)
	if err != nil {
		t.Fatal(err)
	}
	blacklist.AddTables([]string{"z", "Shippers"})
	_, err = blacklist.CheckQuery(testQuery)
	if err != handlers.ErrAccessToForbiddenTableBlacklist {
		t.Fatal(err)
	}
	whitelist := handlers.NewWhitelistHandler()
	whitelist.AddTables([]string{"Orders", "Customers", "NotShippers"})
	_, err = whitelist.CheckQuery(testQuery)
	if err != handlers.ErrAccessToForbiddenTableWhitelist {
		t.Fatal(err)
	}
	whitelist.AddTables([]string{"Shippers"})
	_, err = whitelist.CheckQuery(testQuery)
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
	whitelist := handlers.NewWhitelistHandler()
	whitelist.AddTables([]string{"some table"})
	blacklist := handlers.NewBlacklistHandler()
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
	checkHandler([]QueryHandlerInterface{whitelist}, handlers.ErrQuerySyntaxError)
	checkHandler([]QueryHandlerInterface{blacklist}, handlers.ErrQuerySyntaxError)
	// check when censor with two handlers and each one will return query parse error
	checkHandler([]QueryHandlerInterface{whitelist, blacklist}, handlers.ErrQuerySyntaxError)
	acraCensor.ignoreParseError = true
	checkHandler([]QueryHandlerInterface{whitelist}, nil)
	checkHandler([]QueryHandlerInterface{blacklist}, nil)
	// check when censor with two handlers and each one will return query parse error
	checkHandler([]QueryHandlerInterface{whitelist, blacklist}, nil)
}
