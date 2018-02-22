package firewall

import (
	"testing"
	"github.com/mitchellh/go-homedir"
)


func TestGeneral(t *testing.T) {

	sqlSelectQueries := [...]string {
		"SELECT * FROM Schema.Tables;","SELECT * FROM Schema.Tables;","SELECT * FROM Schema.Tables;","SELECT * FROM Schema.Tables;","SELECT * FROM Schema.Tables;","SELECT * FROM Schema.Tables;","SELECT * FROM Schema.Tables;","SELECT * FROM Schema.Tables;","SELECT * FROM Schema.Tables;","SELECT * FROM Schema.Tables;","SELECT * FROM Schema.Tables;",
		//"SELECT Student_ID FROM STUDENT;",
		//"SELECT * FROM STUDENT;",
		//"SELECT EMP_ID, NAME FROM EMPLOYEE_TBL WHERE EMP_ID = '0000';",
		//"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		//"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE_TBL WHERE CITY = 'INDIANAPOLIS' ORDER BY EMP_ID asc;",
		//"SELECT Name, Age FROM Patients WHERE Age > 40 GROUP BY Age ORDER BY Name;",
		//"SELECT COUNT(CustomerID), Country FROM Customers GROUP BY Country;",
		//"SELECT SUM(Salary)FROM Employee WHERE Emp_Age < 30;",
		//"SELECT AVG(Price)FROM Products;",
		//"SELECT * FROM Schema.views;",
	}

	sqlInsertQueries := [...]string {
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

	if len(sqlSelectQueries) != 11{
		t.Fatal("not equal")
	}

	if len(sqlInsertQueries) != 10{
		t.Fatal("not equal")
	}

	home, err := homedir.Dir()
	if err != nil {
		t.Fatal("can't get $HOME directory")
	}

	firewall, err := NewFilesystemAcraFirewall(home)
	if err != nil {
		t.Fatal("can't create firewall engine")
	}

	for i := 0; i < len(sqlSelectQueries); i++ {
		firewall.ProcessQuery(sqlSelectQueries[i])
	}

	for i := 0; i < len(sqlInsertQueries); i++ {
		firewall.ProcessQuery(sqlInsertQueries[i])
	}

	//storedQueries := firewall.GetStoredQueries()
	//
	//if len(storedQueries) != 21 {
	//	t.Fatal("error ")
	//}

}