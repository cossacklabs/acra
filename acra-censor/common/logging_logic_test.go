package common

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSerializationOnUniqueQueries(t *testing.T) {
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
	writer, err := NewFileQueryWriter(tmpFile.Name())

	defer func() {
		writer.Release()
		err = os.Remove(tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}
	}()

	if err != nil {
		t.Fatal(err)
	}
	for _, query := range testQueries {
		_, err = writer.RedactAndCheckQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}
	defaultTimeout := writer.GetSerializationTimeout()
	writer.SetSerializationTimeout(50 * time.Millisecond)
	//wait until goroutine handles complex serialization
	time.Sleep(defaultTimeout + writer.GetSerializationTimeout() + 10*time.Millisecond)
	if len(writer.GetAllInputQueries()) != len(testQueries) {
		t.Fatal("Expected: " + strings.Join(testQueries, " | ") + "\nGot: " + strings.Join(writer.GetAllInputQueries(), " | "))
	}
	err = writer.DumpQueries()
	if err != nil {
		t.Fatal(err)
	}
	writer.reset()
	if len(writer.GetAllInputQueries()) != 0 {
		t.Fatal("Expected no queries \nGot: " + strings.Join(writer.GetAllInputQueries(), " | "))
	}
	err = writer.readStoredQueries()
	if err != nil {
		t.Fatal(err)
	}
	if len(writer.GetAllInputQueries()) != len(testQueries) {
		t.Fatal("Expected: " + strings.Join(testQueries, " | ") + "\nGot: " + strings.Join(writer.GetAllInputQueries(), " | "))
	}
	for index, query := range writer.GetAllInputQueries() {
		if strings.EqualFold(testQueries[index], query) {
			t.Fatal("Expected: " + testQueries[index] + "\nGot: " + query)
		}
	}
}
func TestSerializationOnSameQueries(t *testing.T) {
	// 5 queries, 3 unique redacted queries
	numOfUniqueQueries := 3
	testQueries := []string{
		// will be redacted
		"SELECT NAME WHERE EMP_ID = '1234';",
		"SELECT NAME WHERE EMP_ID = '345';",

		// different
		"SELECT EMP_ID, LAST_NAME FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",
		"SELECT EMP_ID FROM EMPLOYEE WHERE CITY = 'Seattle' ORDER BY EMP_ID;",

		// similar to previous one, will be redacted
		"SELECT EMP_ID FROM EMPLOYEE WHERE CITY = 'London' ORDER BY EMP_ID;",
	}
	tmpFile, err := ioutil.TempFile("", "censor_log")
	if err != nil {
		t.Fatal(err)
	}
	if err = tmpFile.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := NewFileQueryWriter(tmpFile.Name())

	defer func() {
		writer.Release()
		err = os.Remove(tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}
	}()

	if err != nil {
		t.Fatal(err)
	}
	for _, query := range testQueries {
		_, err = writer.RedactAndCheckQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}
	defaultTimeout := writer.GetSerializationTimeout()
	writer.SetSerializationTimeout(50 * time.Millisecond)
	//wait until goroutine handles complex serialization
	time.Sleep(defaultTimeout + writer.GetSerializationTimeout() + 10*time.Millisecond)

	if len(writer.GetAllInputQueries()) != numOfUniqueQueries {
		t.Fatal("Expected to have " + fmt.Sprint(numOfUniqueQueries) + " unique queries. \n Got:" + strings.Join(writer.GetAllInputQueries(), " | "))
	}
	err = writer.DumpQueries()
	if err != nil {
		t.Fatal(err)
	}
	writer.reset()
	if len(writer.GetAllInputQueries()) != 0 {
		t.Fatal("Expected no queries \nGot: " + strings.Join(writer.GetAllInputQueries(), " | "))
	}
	err = writer.readStoredQueries()
	if err != nil {
		t.Fatal(err)
	}
	if len(writer.GetAllInputQueries()) != numOfUniqueQueries {
		t.Fatal("Expected to have " + fmt.Sprint(numOfUniqueQueries) + " unique queries. \n Got:" + strings.Join(writer.GetAllInputQueries(), " | "))
	}
	for index, query := range writer.GetAllInputQueries() {
		if strings.EqualFold(testQueries[index], query) {
			t.Fatal("Expected: " + testQueries[index] + "\nGot: " + query)
		}
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
	writer, err := NewFileQueryWriter(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		writer.Release()
		err = os.Remove(tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}
	}()
	testQueries := []string{
		"SELECT Student_ID FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT * FROM X;",
		"SELECT * FROM Y;",
	}
	for _, query := range testQueries {
		_, err = writer.RedactAndCheckQuery(query)
		if err != nil {
			t.Fatal(err)
		}
	}
	expected := "{\"raw_query\":\"SELECT Student_ID FROM STUDENT\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM STUDENT\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM X\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM Y\",\"_blacklisted_by_web_config\":false}\n"

	defaultTimeout := writer.GetSerializationTimeout()
	writer.SetSerializationTimeout(50 * time.Millisecond)
	//wait until goroutine handles complex serialization
	time.Sleep(defaultTimeout + writer.GetSerializationTimeout() + extraWaitTime)
	result, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(strings.ToUpper(string(result)), strings.ToUpper(expected)) {
		t.Fatal("Expected: " + expected + "\nGot: " + string(result))
	}
	testQuery := "SELECT * FROM Z;"
	_, err = writer.RedactAndCheckQuery(testQuery)
	if err != nil {
		t.Fatal(err)
	}
	expected = "{\"raw_query\":\"SELECT Student_ID FROM STUDENT\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM STUDENT\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM X\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM Y\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM Z\",\"_blacklisted_by_web_config\":false}\n"

	time.Sleep(writer.GetSerializationTimeout() + extraWaitTime)
	result, err = ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(strings.ToUpper(string(result)), strings.ToUpper(expected)) {
		t.Fatal("Expected: " + expected + "\nGot: " + string(result))
	}

	//Check that values are hidden while logging
	testQuery = "select songName from t where personName in ('Ryan', 'Holly') group by songName having count(distinct personName) = 10"

	writer.RedactAndCheckQuery(testQuery)

	//wait until serialization completes
	time.Sleep(writer.GetSerializationTimeout() + extraWaitTime)

	result, err = ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	expectedPrefix := "{\"raw_query\":\"SELECT Student_ID FROM STUDENT\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM STUDENT\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM X\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM Y\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM Z\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"select songName from t where personName in"

	suffix := strings.TrimPrefix(strings.ToUpper(string(result)), strings.ToUpper(expectedPrefix))

	//we expect TWO placeholders here: instead of "('Ryan', 'Holly')" and instead of "10"
	if strings.Count(suffix, strings.ToUpper(ValueMask)) != 2 {
		t.Fatal("unexpected placeholder values in following: " + string(result))
	}

	if strings.Contains(strings.ToUpper(string(result)), strings.ToUpper("Ryan")) ||
		strings.Contains(strings.ToUpper(string(result)), strings.ToUpper("Holly")) ||
		strings.Contains(strings.ToUpper(string(result)), strings.ToUpper("10")) {
		t.Fatal("values detected in logs: " + string(result))
	}
}
