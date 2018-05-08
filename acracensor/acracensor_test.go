package acracensor

import (
	"github.com/cossacklabs/acra/acracensor/handlers"
	"io/ioutil"
	"os"
	"testing"
	"strings"
	"time"
	"github.com/cossacklabs/acra/utils"
	"path/filepath"
)

func TestWhitelistQueries(t *testing.T) {

	sqlSelectQueries := []string{
		"SELECT * FROM Schema.Tables;",
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
		"SELECT * FROM Schema.Tables;",
		"SELECT * FROM Schema.Tables;",
		"SELECT * FROM Schema.Tables;",
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

func TestSerialization(t *testing.T){
	testQueries := []string{
		"SELECT * FROM Schema.Tables;",
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
	defer loggingHandler.Release()
	if err != nil {
		t.Fatal(err)
	}

	for _, query := range testQueries {
		err = loggingHandler.CheckQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	loggingHandler.SetSerializationTimeout(50 * time.Millisecond)
	//wait until serialization complete
	time.Sleep(loggingHandler.GetSerializationTimeout() + 50 * time.Millisecond)

	if len(loggingHandler.GetAllInputQueries()) != len(testQueries){
		t.Fatal("Expected: " + strings.Join(testQueries, " | ") + "\nGot: " + strings.Join(loggingHandler.GetAllInputQueries(), " | "))
	}

	err = loggingHandler.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	loggingHandler.Reset()

	if len(loggingHandler.GetAllInputQueries()) != 0 {
		t.Fatal("Expected no queries \nGot: " + strings.Join(loggingHandler.GetAllInputQueries(), " | "))
	}

	err = loggingHandler.Deserialize()
	if err != nil {
		t.Fatal(err)
	}

	if len(loggingHandler.GetAllInputQueries()) != len(testQueries){
		t.Fatal("Expected: " + strings.Join(testQueries, " | ") + "\nGot: " + strings.Join(loggingHandler.GetAllInputQueries(), " | "))
	}

	for index, query := range loggingHandler.GetAllInputQueries(){
		if testQueries[index] != query{
			t.Fatal("Expected: " + testQueries[index] + "\nGot: " + query)
		}
	}

	if err = os.Remove(tmpFile.Name()); err != nil {
		t.Fatal(err)
	}
}
func TestLogging(t *testing.T){

	testQueries := []string{
		"SELECT * FROM Schema.Tables;",
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

	loggingHandler.Serialize()

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
func TestQueryCapture(t *testing.T){

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
		"SELECT * FROM Schema.Tables;",
		"SELECT Student_ID FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT * FROM X;",
		"SELECT * FROM Y;",
	}

	for _, query := range testQueries{
		err = handler.CheckQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	expected := "[{\"RawQuery\":\"SELECT * FROM Schema.Tables;\",\"IsForbidden\":false},{\"RawQuery\":\"SELECT Student_ID FROM STUDENT;\",\"IsForbidden\":false},{\"RawQuery\":\"SELECT * FROM STUDENT;\",\"IsForbidden\":false},{\"RawQuery\":\"SELECT * FROM X;\",\"IsForbidden\":false},{\"RawQuery\":\"SELECT * FROM Y;\",\"IsForbidden\":false}]"

	handler.SetSerializationTimeout(50 * time.Millisecond)

	//wait until goroutine handles complex serialization
	time.Sleep(handler.GetSerializationTimeout() + 50 * time.Millisecond)
	result, err := ioutil.ReadFile(tmpFile.Name())
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

	var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName("acra_censor.example")

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

	handlers_, err := acraCensor.LoadConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}

	testQueries := []string{
		"INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');",
		"SELECT AVG(Price) FROM Products;",
	}

	//acracensor should block those queries (blacklist works)
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

	//acracensor should block those tables (blacklist works)
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

	//acracensor should block those structures (blacklist works)
	for _, queryToBlock := range testQueries {
		err = acraCensor.HandleQuery(queryToBlock)
		if err != handlers.ErrForbiddenSqlStructureBlacklist {
			t.Fatal(err)
		}
	}

	testQueries = []string{
		"SELECT EMP_ID, LAST_NAME FROM PRODUCTS WHERE CITY='INDIANAPOLIS' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM PRODUCTS WHERE CITY='INDIANAPOLIS' ORDER BY EMP_ID asc;",
	}

	//acracensor should block those tables (whitelist works)
	for _, queryToBlock := range testQueries {
		err = acraCensor.HandleQuery(queryToBlock)
		if err != handlers.ErrAccessToForbiddenTableWhitelist {
			t.Fatal(err)
		}
	}

	for _, currentHandler := range handlers_ {
		original, ok := currentHandler.(*handlers.QueryCaptureHandler)
		if ok {
			original.SetSerializationTimeout(50 * time.Millisecond)
			time.Sleep(original.GetSerializationTimeout() + 50 * time.Millisecond)
		}
	}

	//
	//expectedQueriesInCensorLog := "[{\"RawQuery\":\"INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');\",\"IsForbidden\":false},{\"RawQuery\":\"SELECT AVG(Price) FROM Products;\",\"IsForbidden\":false},{\"RawQuery\":\"INSERT INTO EMPLOYEE_TBL VALUES (1, 'Stephen', 'Jiang');\",\"IsForbidden\":false},{\"RawQuery\":\"SELECT AVG(Price) FROM Customers;\",\"IsForbidden\":false},{\"RawQuery\":\"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;\",\"IsForbidden\":false},{\"RawQuery\":\"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE AS EMPL WHERE CITY = 'Seattle' ORDER BY EMP_ID;\",\"IsForbidden\":false},{\"RawQuery\":\"SELECT EMP_ID, LAST_NAME FROM PRODUCTS WHERE CITY='INDIANAPOLIS' ORDER BY EMP_ID;\",\"IsForbidden\":false},{\"RawQuery\":\"SELECT EMP_ID, LAST_NAME FROM PRODUCTS WHERE CITY='INDIANAPOLIS' ORDER BY EMP_ID asc;\",\"IsForbidden\":false}]"
	//
	//censorLogsBytes, err := ioutil.ReadFile("censor_log")
	//if err != nil {
	//	t.Fatal(err)
	//}
	//
	//if !strings.EqualFold(expectedQueriesInCensorLog, string(censorLogsBytes)){
	//	t.Fatal("Expected: " + expectedQueriesInCensorLog + " Got: " + string(censorLogsBytes))
	//}

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
  - handler: blacklist
    queries:
      - INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');
      - SLECT AVG(Price) FROM Products;`

	_, err := acraCensor.LoadConfiguration([]byte(configuration))
	if err != handlers.ErrQuerySyntaxError {
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

	_, err = acraCensor.LoadConfiguration([]byte(configuration))
	if err != handlers.ErrStructureSyntaxError {
		t.Fatal(err)
	}
}