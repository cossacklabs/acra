package common

import (
	"bytes"
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
	go writer.Start()

	defer func() {
		writer.Free()
		err = os.Remove(tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}
	}()

	if err != nil {
		t.Fatal(err)
	}

	for _, query := range testQueries {
		_, queryWithHiddenValues, _, err := HandleRawSQLQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		writer.captureQuery(queryWithHiddenValues)
		if err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(DefaultSerializationTimeout + 100*time.Millisecond)
	if len(writer.Queries) != len(testQueries) {
		t.Fatal("Expected: " + strings.Join(testQueries, " | ") + "\nGot: " + strings.Join(rawStrings(writer.Queries), " | "))
	}
	err = writer.DumpQueries()
	if err != nil {
		t.Fatal(err)
	}
	if len(writer.Queries) != 0 {
		t.Fatal("Expected no queries \nGot: " + strings.Join(rawStrings(writer.Queries), " | "))
	}
	if writer.queryIndex != 0 {
		t.Fatalf("Expected queryIndex == 0 but queryIndex = %d", writer.queryIndex)
	}
	err = writer.readStoredQueries()
	if err != nil {
		t.Fatal(err)
	}
	if len(writer.Queries) != len(testQueries) {
		t.Fatal("Expected: " + strings.Join(testQueries, " | ") + "\nGot: " + strings.Join(rawStrings(writer.Queries), " | "))
	}
	for index, query := range writer.Queries {
		if strings.EqualFold(testQueries[index], query.RawQuery) {
			t.Fatal("Expected: " + testQueries[index] + "\nGot: " + query.RawQuery)
		}
	}
}

func TestOutputFileAfterDumpStoredQueries(t *testing.T) {
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
	writer, err := NewFileQueryWriter(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	testQuery := "select 1 from dual"
	writer.captureQuery(testQuery)
	if err = writer.DumpQueries(); err != nil {
		t.Fatal(err)
	}
	writer.reset()

	if err = writer.readStoredQueries(); err != nil {
		t.Fatal(err)
	}
	if writer.queryIndex != 1 {
		t.Fatal("Expected queryIndex == 1")
	}
	if len(writer.Queries) != 1 {
		t.Fatal("Expected len(writer.Queries) != 1")
	}
	if err = writer.dumpBufferedQueries(); err != nil {
		t.Fatal(err)
	}
	dumpedLines, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	queries := bytes.Split(dumpedLines, []byte{'\n'})

	// 1 expected query and 1 empty line from endline symbol
	if len(queries) != 2 && !bytes.Equal(queries[1], []byte{}) {
		t.Fatalf("Expected 1 dumped query, took %d: %s\n", len(queries), string(dumpedLines))
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
		writer.Free()
		err := os.Remove(tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}
	}()

	if err != nil {
		t.Fatal(err)
	}

	go writer.Start()

	for _, query := range testQueries {
		_, queryWithHiddenValues, _, err := HandleRawSQLQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		writer.captureQuery(queryWithHiddenValues)
		if err != nil {
			t.Fatal(err)
		}
	}

	time.Sleep(DefaultSerializationTimeout + 100*time.Millisecond)

	if len(writer.Queries) != numOfUniqueQueries {
		t.Fatal("Expected to have " + fmt.Sprint(numOfUniqueQueries) + " unique queries. \n Got:" + strings.Join(rawStrings(writer.Queries), " | "))
	}
	err = writer.DumpQueries()
	if err != nil {
		t.Fatal(err)
	}
	writer.reset()
	if len(writer.Queries) != 0 {
		t.Fatal("Expected no queries \nGot: " + strings.Join(rawStrings(writer.Queries), " | "))
	}
	err = writer.readStoredQueries()
	if err != nil {
		t.Fatal(err)
	}
	if len(writer.Queries) != numOfUniqueQueries {
		t.Fatal("Expected to have " + fmt.Sprint(numOfUniqueQueries) + " unique queries. \n Got:" + strings.Join(rawStrings(writer.Queries), " | "))
	}
	for index, query := range writer.Queries {
		if strings.EqualFold(testQueries[index], query.RawQuery) {
			t.Fatal("Expected: " + testQueries[index] + "\nGot: " + query.RawQuery)
		}
	}
}
func TestQueryCaptureOnDuplicates(t *testing.T) {
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
	defer func() {
		writer.Free()
		err = os.Remove(tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}
	}()
	if err != nil {
		t.Fatal(err)
	}

	go writer.Start()

	testQueries := []string{
		"SELECT Student_ID FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT * FROM X;",
		"SELECT * FROM X;",
	}

	for _, query := range testQueries {
		writer.WriteQuery(query)
	}
	expected := "{\"raw_query\":\"SELECT Student_ID FROM STUDENT;\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM STUDENT;\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM X;\",\"_blacklisted_by_web_config\":false}\n"

	time.Sleep(DefaultSerializationTimeout + extraWaitTime)
	result, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(strings.ToUpper(string(result)), strings.ToUpper(expected)) {
		t.Fatal("Expected: " + expected + "\nGot: " + string(result))
	}
	testQuery := "SELECT * FROM Z;"
	writer.WriteQuery(testQuery)
	expected = "{\"raw_query\":\"SELECT Student_ID FROM STUDENT;\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM STUDENT;\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM X;\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM Z;\",\"_blacklisted_by_web_config\":false}\n"
	time.Sleep(DefaultSerializationTimeout + extraWaitTime)
	result, err = ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(strings.ToUpper(string(result)), strings.ToUpper(expected)) {
		t.Fatal("Expected: " + expected + "\nGot: " + string(result))
	}

	//Check that values are hidden while logging
	testQuery = "select songName from t where personName in ('Ryan', 'Holly') group by songName having count(distinct personName) = 10"
	writer.WriteQuery(testQuery)
	//wait until serialization completes
	time.Sleep(DefaultSerializationTimeout + extraWaitTime)

	result, err = ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	expected = "{\"raw_query\":\"SELECT Student_ID FROM STUDENT;\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM STUDENT;\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM X;\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"SELECT * FROM Z;\",\"_blacklisted_by_web_config\":false}\n" +
		"{\"raw_query\":\"select songName from t where personName in ('Ryan', 'Holly') group by songName having count(distinct personName) = 10\",\"_blacklisted_by_web_config\":false}\n"

	if !strings.EqualFold(expected, string(result)) {
		t.Fatal("Expected: ", expected, " | Got: ", string(result))
	}
}

func rawStrings(input []*QueryInfo) []string {
	var result []string
	for _, queryInfo := range input {
		result = append(result, queryInfo.RawQuery)
	}
	return result
}
