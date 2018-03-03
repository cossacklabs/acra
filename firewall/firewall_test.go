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

	whitelistHandler, err := handlers.NewWhitelistHandler([]string{"SELECT * FROM Schema.Tables;", "SELECT Student_ID FROM STUDENT;", "SELECT * FROM STUDENT;"})
	if err != nil {
		t.Fatal("can't create whitelist handler")
	}
	whitelistHandler.AddQueriesToWhitelist(sqlSelectQueries)
	whitelistHandler.AddQueriesToWhitelist(sqlInsertQueries)

	firewall := &Firewall{}

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
}

func TestBlacklistFirewall(t *testing.T) {
	sqlSelectQueries := []string {
		"SELECT * FROM Schema.Tables;",
		"SELECT Student_ID FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT EMP_ID, NAME FROM EMPLOYEE_TBL WHERE EMP_ID = '0000';",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		"SELECT Name, Age FROM Patients WHERE Age > 40 GROUP BY Age ORDER BY Name;",
		"SELECT COUNT(CustomerID), Country FROM Customers GROUP BY Country;",
		"SELECT SUM(Salary)FROM Employee WHERE Emp_Age < 30;",
		//"SELECT AVG(Price)FROM Products;",
		"SELECT * FROM Schema.views;",
	}

	sqlInsertQueries := []string {
		//"INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');",
		"INSERT SalesStaff1 VALUES (2, 'Michael', 'Blythe'), (3, 'Linda', 'Mitchell'),(4, 'Jillian', 'Carson'), (5, 'Garrett', 'Vargas');",
		"INSERT INTO SalesStaff2 (StaffGUID, FirstName, LastName) VALUES (NEWID(), 'Stephen', 'Jiang');",
		"INSERT INTO SalesStaff3 (StaffID, FullName)",
		"INSERT INTO Customers (CustomerName, ContactName, Address, City, PostalCode, Country) VALUES ('Cardinal', 'Tom B. Erichsen', 'Skagen 21', 'Stavanger', '4006', 'Norway');",
		"INSERT INTO Customers (CustomerName, City, Country) VALUES ('Cardinal', 'Stavanger', 'Norway');",
		"INSERT INTO Production.UnitMeasure (Name, UnitMeasureCode,	ModifiedDate) VALUES (N'Square Yards', N'Y2', GETDATE());",
		"INSERT INTO T1 DEFAULT VALUES;",
		"INSERT INTO dbo.Points (PointValue) VALUES (CONVERT(Point, '1,5'));",
		"INSERT INTO dbo.Points (PointValue) VALUES (CAST ('1,99' AS Point));",
	}

	blackList := [] string {
		"INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');",
		"SELECT AVG(Price)FROM Products;",
	}

	blacklistHandler, err := handlers.NewBlacklistHandler(blackList)
	if err != nil {
		t.Fatal("can't create blacklist handler")
	}

	firewall := &Firewall{}

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

	testQuery := "INSERT INTO dbo.Points (PointValue) VALUES (CONVERT(Point, '1,5'));";

	blacklistHandler.AddQueriesToBlacklist([]string{testQuery})

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

	blacklistHandler.RemoveQueriesFromBlacklist([]string{testQuery})

	err = firewall.HandleQuery(testQuery)
	//now firewall should not block testQuery
	if err != nil {
		t.Fatal(err)
	}

}