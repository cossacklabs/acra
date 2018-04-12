package acracensor

import (
	"github.com/cossacklabs/acra/acracensor/handlers"
	"github.com/cossacklabs/acra/utils"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
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

	firewall := &Firewall{}

	//set our acracensor to use whitelist for query evaluating
	firewall.AddHandler(whitelistHandler)

	//acracensor should not block those queries
	for _, query := range sqlSelectQueries {
		err = firewall.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, query := range sqlInsertQueries {
		err = firewall.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	//acracensor should block this query because it is not in whitelist
	err = firewall.HandleQuery("SELECT * FROM Schema.views;")
	if err != handlers.ErrQueryNotInWhitelist {
		t.Fatal(err)
	}

	//ditto
	err = firewall.HandleQuery("INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');")
	if err != handlers.ErrQueryNotInWhitelist {
		t.Fatal(err)
	}

	testWhitelistTables(t, firewall, whitelistHandler)
	testWhitelistRules(t, firewall, whitelistHandler)
}
func testWhitelistTables(t *testing.T, firewall *Firewall, whitelistHandler *handlers.WhitelistHandler) {

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
		err := firewall.HandleQuery(testQueries[i])
		if err != handlers.ErrAccessToForbiddenTableWhitelist {
			t.Fatal(err)
		}
	}

	err := firewall.HandleQuery(testQueries[1])
	//acracensor should not block this query
	if err != nil {
		t.Fatal(err)
	}

	//Now we have no tables in whitelist, so should block all queries
	whitelistHandler.RemoveTables([]string{"EMPLOYEE"})

	//acracensor should not block queries
	for _, query := range testQueries {
		err = firewall.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	testQuery := "SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL, CUSTOMERS WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;"

	whitelistHandler.AddQueries([]string{testQuery})
	whitelistHandler.AddTables([]string{"EMPLOYEE", "EMPLOYEE_TBL"})

	err = firewall.HandleQuery(testQuery)

	//acracensor should block this query
	if err != handlers.ErrAccessToForbiddenTableWhitelist {
		t.Fatal(err)
	}

	whitelistHandler.AddTables([]string{"CUSTOMERS"})

	err = firewall.HandleQuery(testQuery)

	//acracensor should not block this query
	if err != nil {
		t.Fatal(err)
	}
}
func testWhitelistRules(t *testing.T, firewall *Firewall, whitelistHandler *handlers.WhitelistHandler) {
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
		err := firewall.HandleQuery(testQueries[i])
		if err != handlers.ErrForbiddenSqlStructureWhitelist {
			t.Fatal(err)
		}
	}

	queryIndexesToPass := []int{0, 4}
	//acracensor should not block those queries
	for _, i := range queryIndexesToPass {
		err := firewall.HandleQuery(testQueries[i])
		if err != nil {
			t.Fatal(err)
		}
	}

	whitelistHandler.RemoveRules(testSecurityRules)
	//acracensor should not block all queries
	for _, query := range testQueries {
		err := firewall.HandleQuery(query)
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

	firewall := &Firewall{}

	//set our acracensor to use blacklist for query evaluating
	firewall.AddHandler(blacklistHandler)

	//acracensor should not block those queries
	for _, query := range sqlSelectQueries {
		err = firewall.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, query := range sqlInsertQueries {
		err = firewall.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	testQuery := "INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');"

	err = blacklistHandler.AddQueries([]string{testQuery})
	if err != nil {
		t.Fatal(err)
	}

	err = firewall.HandleQuery(testQuery)
	//acracensor should block this query because it's in blacklist
	if err != handlers.ErrQueryInBlacklist {
		t.Fatal(err)
	}

	firewall.RemoveHandler(blacklistHandler)

	err = firewall.HandleQuery(testQuery)
	//acracensor should not block this query because we removed blacklist handler, err should be nil
	if err != nil {
		t.Fatal(err)
	}

	//again set our acracensor to use blacklist for query evaluating
	firewall.AddHandler(blacklistHandler)
	err = firewall.HandleQuery(testQuery)

	//now acracensor should block testQuery because it's in blacklist
	if err != handlers.ErrQueryInBlacklist {
		t.Fatal(err)
	}

	blacklistHandler.RemoveQueries([]string{testQuery})

	err = firewall.HandleQuery(testQuery)
	//now acracensor should not block testQuery
	if err != nil {
		t.Fatal(err)
	}

	testBlacklistTables(t, firewall, blacklistHandler)

	testBlacklistRules(t, firewall, blacklistHandler)
}
func testBlacklistTables(t *testing.T, firewall *Firewall, blacklistHandler *handlers.BlacklistHandler) {

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
		err := firewall.HandleQuery(testQueries[i])
		if err != handlers.ErrAccessToForbiddenTableBlacklist {
			t.Fatal(err)
		}
	}

	//acracensor should not block these queries
	queryIndexesToPass := []int{1, 3}
	for _, i := range queryIndexesToPass {
		err := firewall.HandleQuery(testQueries[i])
		if err != nil {
			t.Fatal(err)
		}
	}

	blacklistHandler.RemoveTables([]string{"EMPLOYEE_TBL"})

	err := firewall.HandleQuery(testQueries[0])
	//acracensor should not block this query
	if err != nil {
		t.Fatal(err)
	}

	err = firewall.HandleQuery(testQueries[2])
	//acracensor should not block this query
	if err != nil {
		t.Fatal(err)
	}

}
func testBlacklistRules(t *testing.T, firewall *Firewall, blacklistHandler *handlers.BlacklistHandler) {

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
		err := firewall.HandleQuery(testQueries[i])
		if err != handlers.ErrForbiddenSqlStructureBlacklist {
			t.Fatal(err)
		}
	}

	queryIndexesToPass := []int{1, 3}
	//acracensor should not block those queries
	for _, i := range queryIndexesToPass {
		err := firewall.HandleQuery(testQueries[i])
		if err != nil {
			t.Fatal(err)
		}
	}

	blacklistHandler.RemoveRules(testSecurityRules)
	//acracensor should not block all queries
	for _, query := range testQueries {
		err := firewall.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	testSecurityRules = []string{
		"SELECT * FROM EMPLOYEE_TBL, EMPLOYEE WHERE CITY='Seattle'",
		"SELECT * FROM EMPLOYEE_TBL, EMPLOYEE WHERE CITY='INDIANAPOLIS'",
	}

	blacklistHandler.Reset()
	blacklistHandler.AddRules(testSecurityRules)
	//acracensor should block all queries
	for _, query := range testQueries {
		err := firewall.HandleQuery(query)
		if err != handlers.ErrForbiddenSqlStructureBlacklist {
			t.Fatal(err)
		}
	}
}

func TestConfigurationProvider(t *testing.T) {

	var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName("acra_firewall.example")

	filePath, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	configuration, err := ioutil.ReadFile(filepath.Join(filePath, "../", DEFAULT_CONFIG_PATH))
	if err != nil {
		t.Fatal(err)
	}

	firewall := &Firewall{}

	err = firewall.LoadConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}

	testQueries := []string{
		"INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');",
		"SELECT AVG(Price) FROM Products;",
	}

	//acracensor should block those queries (blacklist works)
	for _, queryToBlock := range testQueries {
		err = firewall.HandleQuery(queryToBlock)
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
		err = firewall.HandleQuery(queryToBlock)
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
		err = firewall.HandleQuery(queryToBlock)
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
		err = firewall.HandleQuery(queryToBlock)
		if err != handlers.ErrAccessToForbiddenTableWhitelist {
			t.Fatal(err)
		}
	}

	testSyntax(t)
}
func testSyntax(t *testing.T) {

	firewall := &Firewall{}

	configuration := `handlers:
  - handler: blacklist
    queries:
      - INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');
      - SLECT AVG(Price) FROM Products;`

	err := firewall.LoadConfiguration([]byte(configuration))
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

	err = firewall.LoadConfiguration([]byte(configuration))
	if err != handlers.ErrStructureSyntaxError {
		t.Fatal(err)
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

	tmpFile, err := ioutil.TempFile("", "firewall_log")
	if err != nil {
		t.Fatal(err)
	}

	if err = tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	loggingHandler := handlers.NewLoggingHandler(tmpFile.Name())
	for _, query := range testQueries {
		loggingHandler.CheckQuery(query)
	}

	if len(loggingHandler.GetAllInputQueries()) != len(testQueries){
		t.Fatal("loggingHandler logic error 1")
	}


	err = loggingHandler.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	loggingHandler.Reset()

	if len(loggingHandler.GetAllInputQueries()) != 0 {
		t.Fatal("loggingHandler logic error 2")
	}

	err = loggingHandler.Deserialize()
	if err != nil {
		t.Fatal(err)
	}

	if len(loggingHandler.GetAllInputQueries()) != len(testQueries){
		t.Fatal("loggingHandler logic error 3")
	}

	for index, query := range loggingHandler.GetAllInputQueries(){
		if testQueries[index] != query{
			t.Fatal("loggingHandler logic error 4")
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

	tmpFile, err := ioutil.TempFile("", "firewall_log")
	if err != nil {
		t.Fatal(err)
	}

	if err = tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	loggingHandler := handlers.NewLoggingHandler(tmpFile.Name())

	blacklist := &handlers.BlacklistHandler{}

	firewall := &Firewall{}
	firewall.AddHandler(loggingHandler)
	firewall.AddHandler(blacklist)

	for _, testQuery := range testQueries {
		err = firewall.HandleQuery(testQuery)
		if err != nil {
			t.Fatal(err)
		}
	}

	loggingHandler.MarkQueryAsForbidden(testQueries[0])
	loggingHandler.MarkQueryAsForbidden(testQueries[1])
	loggingHandler.MarkQueryAsForbidden(testQueries[2])

	blacklist.AddQueries(loggingHandler.GetForbiddenQueries())

	err = firewall.HandleQuery(testQueries[0])
	if err != handlers.ErrQueryInBlacklist {
		t.Fatal(err)
	}

	err = firewall.HandleQuery(testQueries[1])
	if err != handlers.ErrQueryInBlacklist {
		t.Fatal(err)
	}

	err = firewall.HandleQuery(testQueries[2])
	if err != handlers.ErrQueryInBlacklist {
		t.Fatal(err)
	}

	//zero, first and second query are forbidden
	for index := 3; index < len(testQueries); index++ {
		err = firewall.HandleQuery(testQueries[index])
		if err != nil {
			t.Fatal(err)
		}
	}

	if err = os.Remove(tmpFile.Name()); err != nil {
		t.Fatal(err)
	}
}
