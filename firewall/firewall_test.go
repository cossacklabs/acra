package firewall

import (
	"testing"
	"github.com/cossacklabs/acra/firewall/handlers"
)


func TestWhitelistFirewall(t *testing.T) {

	sqlSelectQueries := []string {
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
		//"SELECT * FROM Schema.views;",
	}

	sqlInsertQueries := []string {
		//"INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');",
		"INSERT SalesStaff1 VALUES (2, 'Michael', 'Blythe'), (3, 'Linda', 'Mitchell'),(4, 'Jillian', 'Carson'), (5, 'Garrett', 'Vargas');",
		"INSERT INTO SalesStaff2 (StaffGUID, FirstName, LastName) VALUES (NEWID(), 'Stephen', 'Jiang');",
		"INSERT INTO SalesStaff3 (StaffID, FullName)",
		"INSERT INTO SalesStaff3 (StaffID, FullName)",
		"INSERT INTO SalesStaff3 (StaffID, FullName)",
		"INSERT INTO Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"INSERT INTO Production.UnitMeasure (Name, UnitMeasureCode,	ModifiedDate) VALUES (N'Square Yards', N'Y2', GETDATE());",
		"INSERT INTO T1 DEFAULT VALUES;",
		"INSERT INTO dbo.Points (PointValue) VALUES (CONVERT(Point, '1,5'));",
		"INSERT INTO dbo.Points (PointValue) VALUES (CAST ('1,99' AS Point));",
	}

	whitelistHandler := &handlers.WhitelistHandler{}

	whitelistHandler.AddQueries(sqlSelectQueries)
	whitelistHandler.AddQueries(sqlInsertQueries)

	firewall := &Firewall{}

	var err error

	//set our firewall to use whitelist for query evaluating
	firewall.AddHandler(whitelistHandler)

	for _, query := range sqlSelectQueries{
		err = firewall.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, query := range sqlInsertQueries{
		err = firewall.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	//firewall should block this query because it is not in whitelist
	err = firewall.HandleQuery("SELECT * FROM Schema.views;")
	if err == nil {
		t.Fatal(err)
	}

	//ditto
	err = firewall.HandleQuery("INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');")
	if err == nil {
		t.Fatal(err)
	}

	testWhitelistTables(t, firewall, whitelistHandler)
}
func testWhitelistTables(t *testing.T, firewall * Firewall, whitelistHandler * handlers.WhitelistHandler){

	testQueries := []string {
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

	//firewall should block those queries
	for _, i := range queryIndexesToBlock {
		err := firewall.HandleQuery(testQueries[i])
		if err == nil {
			t.Fatal(err)
		}
	}

	err := firewall.HandleQuery(testQueries[1])
	//firewall should not block this query
	if err != nil {
		t.Fatal(err)
	}

	//Now we have no tables in whitelist, so should block all queries
	whitelistHandler.RemoveTables([]string{"EMPLOYEE"})

	//firewall should not block queries
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

	//firewall should block this query
	if err == nil {
		t.Fatal(err)
	}

	whitelistHandler.AddTables([]string{"CUSTOMERS"})

	err = firewall.HandleQuery(testQuery)

	//firewall should not block this query
	if err != nil {
		t.Fatal(err)
	}
}



func TestBlacklistFirewall(t *testing.T) {
	sqlSelectQueries := []string {
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
		//"SELECT AVG(Price)FROM Products;",
		"SELECT * FROM Schema.views;",
	}

	sqlInsertQueries := []string {
		//"INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');",
		"INSERT SalesStaff1 VALUES (2, 'Michael', 'Blythe'), (3, 'Linda', 'Mitchell'),(4, 'Jillian', 'Carson'), (5, 'Garrett', 'Vargas');",
		"INSERT INTO SalesStaff2 (StaffGUID, FirstName, LastName) VALUES (NEWID(), 'Stephen', 'Jiang');",
		"INSERT INTO Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		//"INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');",
		"INSERT SalesStaff1 VALUES (2, 'Michael', 'Blythe'), (3, 'Linda', 'Mitchell'),(4, 'Jillian', 'Carson'), (5, 'Garrett', 'Vargas');",
		"INSERT INTO SalesStaff2 (StaffGUID, FirstName, LastName) VALUES (NEWID(), 'Stephen', 'Jiang');",
		"INSERT INTO Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"INSERT INTO films VALUES ('UA502', 'Bananas', 105, '1971-07-13', 'Comedy', '82 minutes');",
		"INSERT INTO films (code, title, did, date_prod, kind) VALUES ('B6717', 'Tampopo', 110, '1985-02-10', 'Comedy'), ('HG120', 'The Dinner Game', 140, DEFAULT, 'Comedy');",
		"INSERT INTO films SELECT * FROM tmp_films WHERE date_prod < '2004-05-07';",
	}

	blackList := [] string {
		"INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');",
		"SELECT AVG(Price) FROM Products;",
	}


	blacklistHandler := &handlers.BlacklistHandler{}
	blacklistHandler.AddQueries(blackList)

	firewall := &Firewall{}

	var err error

	//set our firewall to use blacklist for query evaluating
	firewall.AddHandler(blacklistHandler)

	for _, query := range sqlSelectQueries{
		err = firewall.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, query := range sqlInsertQueries{
		err = firewall.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	testQuery := "INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');";

	blacklistHandler.AddQueries([]string{testQuery})

	err = firewall.HandleQuery(testQuery)
	//firewall should block this query by throwing error
	if err == nil {
		t.Fatal(err)
	}

	firewall.RemoveHandler(blacklistHandler)

	err = firewall.HandleQuery(testQuery)
	//firewall should not block this query because we removed blacklist handler, err should be nil
	if err != nil {
		t.Fatal(err)
	}

	//again set our firewall to use blacklist for query evaluating
	firewall.AddHandler(blacklistHandler)

	//now firewall should block testQuery by throwing error
	if err != nil {
		t.Fatal(err)
	}

	blacklistHandler.RemoveQueries([]string{testQuery})

	err = firewall.HandleQuery(testQuery)
	//now firewall should not block testQuery
	if err != nil {
		t.Fatal(err)
	}

	testBlacklistTables(t, firewall, blacklistHandler)

	testBlacklistByRules(t, firewall, blacklistHandler)
}
func testBlacklistTables(t *testing.T, firewall * Firewall, blacklistHandler * handlers.BlacklistHandler){

	blacklistHandler.Refresh()

	testQueries := []string {
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"INSERT INTO Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL AS EMPL_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
	}

	blacklistHandler.AddTables([]string{"EMPLOYEE_TBL", "Customers"})

	//firewall should block these queries
	queryIndexesToBlock := []int {0, 2, 4, 5, 6}
	for _, i := range queryIndexesToBlock {
		err := firewall.HandleQuery(testQueries[i])
		if err == nil {
			t.Fatal(err)
		}
	}

	//firewall should not block these queries
	queryIndexesToPass := []int {1, 3}
	for _, i := range queryIndexesToPass {
		err := firewall.HandleQuery(testQueries[i])
		if err != nil {
			t.Fatal(err)
		}
	}

	blacklistHandler.RemoveTables([]string{"EMPLOYEE_TBL"})

	err := firewall.HandleQuery(testQueries[0])
	//firewall should not block this query
	if err != nil {
		t.Fatal(err)
	}

	err = firewall.HandleQuery(testQueries[2])
	//firewall should not block this query
	if err != nil {
		t.Fatal(err)
	}

}
func testBlacklistByRules(t *testing.T, firewall * Firewall, blacklistHandler * handlers.BlacklistHandler){

	blacklistHandler.Refresh()

	testQueries := []string {
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE, EMPLOYEE_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		//"INSERT INTO Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		//"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL AS EMPL_TBL WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
	}

	//firewall should block all queries that try to access to information in table EMPLOYEE_TBL related to Seattle city
	testSecurityRules := []string {
		"SELECT * FROM EMPLOYEE_TBL WHERE CITY='Seattle'",
	}

	queryIndexesToBlock := []int{0, 2, 4}

	blacklistHandler.AddRules(testSecurityRules)
	//firewall should block those queries
	for _, i := range queryIndexesToBlock {
		err := firewall.HandleQuery(testQueries[i])
		if err != nil {
			if err != handlers.ErrForbiddenSqlStructure {
				t.Fatal(err)
			}
		} else {
			t.Fatal(err)
		}
	}

	queryIndexesToPass := []int{1, 3}
	//firewall should not block those queries
	for _, i := range queryIndexesToPass {
		err := firewall.HandleQuery(testQueries[i])
		if err != nil {
			t.Fatal(err)
		}
	}

	blacklistHandler.RemoveRules(testSecurityRules)
	//firewall should not block all queries
	for _, query := range testQueries {
		err := firewall.HandleQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}

	testSecurityRules = []string {
		"SELECT * FROM EMPLOYEE_TBL, EMPLOYEE WHERE CITY='Seattle'",
		"SELECT * FROM EMPLOYEE_TBL, EMPLOYEE WHERE CITY='INDIANAPOLIS'",
	}

	blacklistHandler.Refresh()
	blacklistHandler.AddRules(testSecurityRules)
	//firewall should block all queries
	for _, query := range testQueries {
		err := firewall.HandleQuery(query)
		if err != nil {
			if err != handlers.ErrForbiddenSqlStructure {
				t.Fatal(err)
			}
		} else {
			t.Fatal(err)
		}
	}
}
