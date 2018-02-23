package firewall

import (
	"testing"
	"github.com/mitchellh/go-homedir"
	"github.com/cossacklabs/acra/firewall/handlers"
)


func TestWhitelistFirewall(t *testing.T) {

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
		"SELECT AVG(Price)FROM Products;",
		"SELECT * FROM Schema.views;",
	}

	sqlInsertQueries := []string {
		"INSERT INTO SalesStaff1 VALUES (1, 'Stephen', 'Jiang');",
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

	home, err := homedir.Dir()
	if err != nil {
		t.Fatal("can't get $HOME directory")
	}

	whitelistHandler, err := handlers.NewWhitelistHandler([]string{"SELECT * FROM Schema.Tables;", "SELECT Student_ID FROM STUDENT;", "SELECT * FROM STUDENT;"})
	if err != nil {
		t.Fatal("can't create whitelist handler")
	}
	whitelistHandler.AddQueriesToWhitelist(sqlSelectQueries)
	whitelistHandler.AddQueriesToWhitelist(sqlInsertQueries)

	firewall, err := NewFilesystemAcraFirewall(home)
	if err != nil {
		t.Fatal("can't create firewall engine")
	}

	//Set our firewall to use whitelist for query evaluating
	firewall.AddSpecificHandler(whitelistHandler)

	for i := 0; i < len(sqlSelectQueries); i++ {
		err = firewall.HandleQuery(sqlSelectQueries[i])
		if err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < len(sqlInsertQueries); i++ {
		err = firewall.HandleQuery(sqlInsertQueries[i])
		if err != nil {
			t.Fatal(err)
		}
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

	home, err := homedir.Dir()
	if err != nil {
		t.Fatal("can't get $HOME directory")
	}


	blacklistHandler, err := handlers.NewBlacklistHandler(blackList)
	if err != nil {
		t.Fatal("can't create blacklist handler")
	}

	firewall, err := NewFilesystemAcraFirewall(home)
	if err != nil {
		t.Fatal("can't create firewall engine")
	}

	//Set our firewall to use blacklist for query evaluating
	firewall.AddSpecificHandler(blacklistHandler)

	for i := 0; i < len(sqlSelectQueries); i++ {
		err = firewall.HandleQuery(sqlSelectQueries[i])
		if err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < len(sqlInsertQueries); i++ {
		err = firewall.HandleQuery(sqlInsertQueries[i])
		if err != nil {
			t.Fatal(err)
		}
	}

	blacklistHandler.AddQueriesToBlacklist([]string{"INSERT INTO dbo.Points (PointValue) VALUES (CONVERT(Point, '1,5'));"})

	err = firewall.HandleQuery("INSERT INTO dbo.Points (PointValue) VALUES (CONVERT(Point, '1,5'));")
	//firewall should block this query by throwing error
	if err == nil {
		t.Fatal(err)
	}

	blacklistHandler.RemoveQueriesFromBlacklist([]string{"INSERT INTO dbo.Points (PointValue) VALUES (CONVERT(Point, '1,5'));"})

	err = firewall.HandleQuery("INSERT INTO dbo.Points (PointValue) VALUES (CONVERT(Point, '1,5'));")
	//now firewall should not block this query
	if err != nil {
		t.Fatal(err)
	}
}
