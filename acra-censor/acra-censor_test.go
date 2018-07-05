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

	whitelistHandler := &handlers.WhitelistHandler{}

	err := whitelistHandler.AddQueries(sqlSelectQueries)
	if err != nil {
		t.Fatal(err)
	}
	err = whitelistHandler.AddQueries(sqlInsertQueries)
	if err != nil {
		t.Fatal(err)
	}

	acraCensor := &AcraCensor{}
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

	testWhitelistTables(t, acraCensor, whitelistHandler)
	testWhitelistRules(t, acraCensor, whitelistHandler)
}
func testWhitelistTables(t *testing.T, acraCensor *AcraCensor, whitelistHandler *handlers.WhitelistHandler) {

	testQueries := []string{
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"INSERT INTO Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL AS EMPL_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
	}

	err := whitelistHandler.AddQueries(testQueries)
	if err != nil {
		t.Fatal(err)
	}

	whitelistHandler.AddTables([]string{"EMPLOYEE"})

	queryIndexesToBlock := []int{0, 2, 3, 4, 5, 6}

	//acracensor should block those queries
	for _, i := range queryIndexesToBlock {
		err := acraCensor.HandleQuery(testQueries[i])
		if err != handlers.ErrAccessToForbiddenTableWhitelist {
			t.Fatal(err)
		}
	}

	err = acraCensor.HandleQuery(testQueries[1])
	//acracensor should not block this query
	if err != nil {
		t.Fatal(err)
	}

	//Now we have no tables in whitelist, so should block all queries
	whitelistHandler.RemoveTables([]string{"EMPLOYEE"})

	//acracensor should not block queries
	for _, query := range testQueries {
		err = acraCensor.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	testQuery := "SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL, CUSTOMERS WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;"

	err = whitelistHandler.AddQueries([]string{testQuery})
	if err != nil {
		t.Fatal(err)
	}
	whitelistHandler.AddTables([]string{"EMPLOYEE", "EMPLOYEE_TBL"})

	err = acraCensor.HandleQuery(testQuery)
	//acracensor should block this query
	if err != handlers.ErrAccessToForbiddenTableWhitelist {
		t.Fatal(err)
	}

	whitelistHandler.AddTables([]string{"CUSTOMERS"})

	err = acraCensor.HandleQuery(testQuery)

	//acracensor should not block this query
	if err != nil {
		t.Fatal(err)
	}
}
func testWhitelistRules(t *testing.T, acraCensor *AcraCensor, whitelistHandler *handlers.WhitelistHandler) {
	whitelistHandler.Reset()

	testQueries := []string{
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL AS EMPL_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
	}

	//acracensor should block all queries except accessing to any information but only in table EMPLOYEE_TBL and related only to Seattle city [1,2,3]
	testSecurityRules := []string{
		"SELECT * FROM EMPLOYEE_TBL WHERE CITY='Seattle'",
	}

	queryIndexesToBlock := []int{1, 2, 3, 5}
	err := whitelistHandler.AddRules(testSecurityRules)
	if err != nil {
		t.Fatal(err)
	}

	//acracensor should block those queries
	for _, i := range queryIndexesToBlock {
		err := acraCensor.HandleQuery(testQueries[i])
		if err != handlers.ErrForbiddenSqlStructureWhitelist {
			t.Fatal(err)
		}
	}

	queryIndexesToPass := []int{0, 4}
	//acracensor should not block those queries
	for _, i := range queryIndexesToPass {
		err := acraCensor.HandleQuery(testQueries[i])
		if err != nil {
			t.Fatal(err)
		}
	}

	whitelistHandler.RemoveRules(testSecurityRules)
	//acracensor should not block all queries
	for _, query := range testQueries {
		err := acraCensor.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestBlacklistQueries(t *testing.T) {
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

	blacklistHandler := &handlers.BlacklistHandler{}
	err := blacklistHandler.AddQueries(blackList)
	if err != nil {
		t.Fatal(err)
	}

	acraCensor := &AcraCensor{}
	defer acraCensor.ReleaseAll()

	//set our acracensor to use blacklist for query evaluating
	acraCensor.AddHandler(blacklistHandler)

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

	err = blacklistHandler.AddQueries([]string{testQuery})
	if err != nil {
		t.Fatal(err)
	}

	err = acraCensor.HandleQuery(testQuery)
	//acracensor should block this query because it's in blacklist
	if err != handlers.ErrQueryInBlacklist {
		t.Fatal(err)
	}

	acraCensor.RemoveHandler(blacklistHandler)

	err = acraCensor.HandleQuery(testQuery)
	//acracensor should not block this query because we removed blacklist handler, err should be nil
	if err != nil {
		t.Fatal(err)
	}

	//again set our acracensor to use blacklist for query evaluating
	acraCensor.AddHandler(blacklistHandler)
	err = acraCensor.HandleQuery(testQuery)

	//now acracensor should block testQuery because it's in blacklist
	if err != handlers.ErrQueryInBlacklist {
		t.Fatal(err)
	}

	blacklistHandler.RemoveQueries([]string{testQuery})

	err = acraCensor.HandleQuery(testQuery)
	//now acracensor should not block testQuery
	if err != nil {
		t.Fatal(err)
	}

	testBlacklistTables(t, acraCensor, blacklistHandler)

	testBlacklistRules(t, acraCensor, blacklistHandler)
}
func testBlacklistTables(t *testing.T, censor *AcraCensor, blacklistHandler *handlers.BlacklistHandler) {

	blacklistHandler.Reset()

	testQueries := []string{
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"INSERT INTO Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL AS EMPL_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
	}

	blacklistHandler.AddTables([]string{"EMPLOYEE_TBL", "Customers"})

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

	blacklistHandler.RemoveTables([]string{"EMPLOYEE_TBL"})

	err := censor.HandleQuery(testQueries[0])
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
func testBlacklistRules(t *testing.T, acraCensor *AcraCensor, blacklistHandler *handlers.BlacklistHandler) {

	blacklistHandler.Reset()

	testQueries := []string{
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL AS EMPL_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
	}

	//acracensor should block all queries that try to access to information in table EMPLOYEE_TBL related to Seattle city
	testSecurityRules := []string{
		"SELECT * FROM EMPLOYEE_TBL WHERE CITY='Seattle'",
	}

	queryIndexesToBlock := []int{0, 2, 4}

	err := blacklistHandler.AddRules(testSecurityRules)
	if err != nil {
		t.Fatal(err)
	}

	//acracensor should block those queries
	for _, i := range queryIndexesToBlock {
		err := acraCensor.HandleQuery(testQueries[i])
		if err != handlers.ErrForbiddenSqlStructureBlacklist {
			t.Fatal(err)
		}
	}

	queryIndexesToPass := []int{1, 3}
	//acracensor should not block those queries
	for _, i := range queryIndexesToPass {
		err := acraCensor.HandleQuery(testQueries[i])
		if err != nil {
			t.Fatal(err)
		}
	}

	blacklistHandler.RemoveRules(testSecurityRules)
	//acracensor should not block all queries
	for _, query := range testQueries {
		err := acraCensor.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	testSecurityRules = []string{
		"SELECT * FROM EMPLOYEE_TBL, EMPLOYEE WHERE CITY='Seattle'",
		"SELECT * FROM EMPLOYEE_TBL, EMPLOYEE WHERE CITY='INDIANAPOLIS'",
	}

	blacklistHandler.Reset()
	err = blacklistHandler.AddRules(testSecurityRules)
	if err != nil {
		t.Fatal(err)
	}
	//acracensor should block all queries
	for _, query := range testQueries {
		err := acraCensor.HandleQuery(query)
		if err != handlers.ErrForbiddenSqlStructureBlacklist {
			t.Fatal(err)
		}
	}
}

func TestQueryIgnoring(t *testing.T) {
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

	acraCensor := &AcraCensor{}
	defer acraCensor.ReleaseAll()

	ignoreQueryHandler := handlers.NewQueryIgnoreHandler()
	ignoreQueryHandler.AddQueries(testQueries)
	acraCensor.AddHandler(ignoreQueryHandler)

	blacklist := &handlers.BlacklistHandler{}
	err := blacklist.AddQueries(testQueries)
	if err != nil {
		t.Fatal(err)
	}
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
		if testQueries[index] != query {
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

	loggingHandler, err := handlers.NewQueryCaptureHandler(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	blacklist := &handlers.BlacklistHandler{}

	acraCensor := &AcraCensor{}
	defer acraCensor.ReleaseAll()
	acraCensor.AddHandler(loggingHandler)
	acraCensor.AddHandler(blacklist)

	for _, testQuery := range testQueries {
		err = acraCensor.HandleQuery(testQuery)
		if err != nil {
			t.Fatal(err)
		}
	}

	loggingHandler.MarkQueryAsForbidden(testQueries[0])
	loggingHandler.MarkQueryAsForbidden(testQueries[1])
	loggingHandler.MarkQueryAsForbidden(testQueries[2])
	loggingHandler.DumpAllQueriesToFile()

	err = blacklist.AddQueries(loggingHandler.GetForbiddenQueries())
	if err != nil {
		t.Fatal(err)
	}

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

	expected := "{\"RawQuery\":\"SELECT Student_ID FROM STUDENT;\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM STUDENT;\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM X;\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM Y;\",\"IsForbidden\":false}\n"

	defaultTimeout := handler.GetSerializationTimeout()
	handler.SetSerializationTimeout(50 * time.Millisecond)
	//wait until goroutine handles complex serialization
	time.Sleep(defaultTimeout + handler.GetSerializationTimeout() + extraWaitTime)

	result, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if !strings.EqualFold(string(result), expected) {
		t.Fatal("Expected: " + expected + "\nGot: " + string(result))
	}

	testQuery := "SELECT * FROM Z;"
	_, err = handler.CheckQuery(testQuery)
	if err != nil {
		t.Fatal(err)
	}

	expected = "{\"RawQuery\":\"SELECT Student_ID FROM STUDENT;\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM STUDENT;\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM X;\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM Y;\",\"IsForbidden\":false}\n" +
		"{\"RawQuery\":\"SELECT * FROM Z;\",\"IsForbidden\":false}\n"
	time.Sleep(handler.GetSerializationTimeout() + extraWaitTime)

	result, err = ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if !strings.EqualFold(string(result), expected) {
		t.Fatal("Expected: " + expected + "\nGot: " + string(result))
	}

	if err = os.Remove(tmpFile.Name()); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationProvider(t *testing.T) {

	var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName("acra-censor.example")

	filePath, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	configuration, err := ioutil.ReadFile(filepath.Join(filePath, "../", DEFAULT_CONFIG_PATH))
	if err != nil {
		t.Fatal(err)
	}

	acraCensor := &AcraCensor{}
	defer acraCensor.ReleaseAll()

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
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE AS EMPL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
	}

	//acracensor should block those structures
	for _, queryToBlock := range testQueries {
		err = acraCensor.HandleQuery(queryToBlock)
		if err != handlers.ErrForbiddenSqlStructureBlacklist {
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

	err = os.Remove("censor_log")
	if err != nil {
		t.Fatal(err)
	}
}
func testSyntax(t *testing.T) {

	acraCensor := &AcraCensor{}
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
    rules:
      - SELECT * ROM EMPLOYEE WHERE CITY='Seattle';`

	err = acraCensor.LoadConfiguration([]byte(configuration))
	if err != handlers.ErrQuerySyntaxError {
		t.Fatal(err)
	}
}

func TestDifferentTablesParsing(t *testing.T) {
	testQuery :=
		"SELECT Orders.OrderID, Customers.CustomerName, Shippers.ShipperName " +
			"FROM ((Orders " +
			"INNER JOIN Customers ON Orders.CustomerID = Customers.CustomerID) " +
			"INNER JOIN Shippers ON Orders.ShipperID = Shippers.ShipperID);"

	blacklist := handlers.BlacklistHandler{}
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

	whitelist := handlers.WhitelistHandler{}
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
	acraCensor := &AcraCensor{}
	defer acraCensor.ReleaseAll()
	whitelistHandler := &handlers.WhitelistHandler{}
	whitelistHandler.AddTables([]string{"some table"})
	blacklistHandler := &handlers.BlacklistHandler{}
	blacklistHandler.AddTables([]string{"some table"})

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

	checkHandler([]QueryHandlerInterface{whitelistHandler}, handlers.ErrQuerySyntaxError)
	checkHandler([]QueryHandlerInterface{blacklistHandler}, handlers.ErrQuerySyntaxError)
	// check when censor with two handlers and each one will return query parse error
	checkHandler([]QueryHandlerInterface{whitelistHandler, blacklistHandler}, handlers.ErrQuerySyntaxError)

	acraCensor.ignoreParseError = true

	checkHandler([]QueryHandlerInterface{whitelistHandler}, nil)
	checkHandler([]QueryHandlerInterface{blacklistHandler}, nil)
	// check when censor with two handlers and each one will return query parse error
	checkHandler([]QueryHandlerInterface{whitelistHandler, blacklistHandler}, nil)
}
