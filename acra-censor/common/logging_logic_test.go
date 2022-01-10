package common

import (
	"bytes"
	"fmt"
	"github.com/cossacklabs/acra/sqlparser"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const testSerializationTime = 100 * time.Millisecond

// sleepTime provide extra time to serialize in background goroutine before check
// default value that will be changed for tests in init function
const sleepTime = testSerializationTime * 3

func initTestWriter(queryWriter *QueryWriter) {
	// change ticker
	queryWriter.serializationTicker = time.NewTicker(testSerializationTime)
}

func TestSerializationOnUniqueQueries(t *testing.T) {
	t.Parallel()
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
	defer func() {
		err = os.Remove(tmpFile.Name())
		if err != nil {
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
	initTestWriter(writer)
	go writer.Start()
	defer writer.Free()

	parser := sqlparser.New(sqlparser.ModeStrict)
	for _, query := range testQueries {
		_, queryWithHiddenValues, _, err := parser.HandleRawSQLQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		writer.captureQuery(queryWithHiddenValues)
	}
	waitQueryProcessing(len(testQueries), writer, t)
	if len(writer.Queries) != len(testQueries) {
		t.Fatal("Expected: " + strings.Join(testQueries, " | ") + "\nGot: " + strings.Join(rawStrings(writer.Queries), " | "))
	}
	err = writer.DumpQueries()
	if err != nil {
		t.Fatal(err)
	}
	writer.reset()
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
	t.Parallel()
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
	initTestWriter(writer)
	testQuery := "select 1 from dual"
	writer.captureQuery(testQuery)
	waitQueryProcessing(1, writer, t)

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
	t.Parallel()
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
	initTestWriter(writer)

	go writer.Start()

	parser := sqlparser.New(sqlparser.ModeStrict)
	for _, query := range testQueries {
		_, queryWithHiddenValues, _, err := parser.HandleRawSQLQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		writer.captureQuery(queryWithHiddenValues)
	}
	waitQueryProcessing(numOfUniqueQueries, writer, t)
	// wait serializationTicker and dumpBufferedQueries call
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
	t.Parallel()
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
	initTestWriter(writer)
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
	if writer.skippedQueryCount > 0 {
		t.Fatal("Detected unexpected skipping queries")
	}
	waitQueryProcessing(3, writer, t)
	// wait serializationTicker and dumpBufferedQueries call
	time.Sleep(sleepTime)

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
	if writer.skippedQueryCount > 0 {
		t.Fatal("Detected unexpected skipping queries")
	}
	waitQueryProcessing(4, writer, t)
	// wait serializationTicker and dumpBufferedQueries call
	time.Sleep(sleepTime)

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
	if writer.skippedQueryCount > 0 {
		t.Fatal("Detected unexpected skipping queries")
	}
	waitQueryProcessing(5, writer, t)
	// wait serializationTicker and dumpBufferedQueries call
	time.Sleep(sleepTime)
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

// TestConcurrentQueryWrite run several background goroutines that write queries at same time.
// Check that nothing blocked and works as expected
func TestConcurrentQueryWrite(t *testing.T) {
	t.Parallel()
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
	// change only ticker period, leave query channel as is
	initTestWriter(writer)

	go writer.Start()

	testQueries := []string{
		"SELECT Student_ID FROM STUDENT;",
		"SELECT * FROM STUDENT;",
		"SELECT * FROM X;",
		"SELECT * FROM X;",
	}

	goroutineCount := 10
	writeLoopCount := 10
	// notify all goroutines to start writing at same time
	condition := sync.NewCond(&sync.Mutex{})
	// wait until all finished
	waitGroup := &sync.WaitGroup{}
	// wait when goroutines ready to start
	run := make(chan struct{}, goroutineCount)
	for i := 0; i < goroutineCount; i++ {
		waitGroup.Add(1)
		// start X background goroutines
		go func(data []string) {
			condition.L.Lock()
			// notify that ready to wait
			run <- struct{}{}
			condition.Wait()

			for i := 0; i < writeLoopCount; i++ {
				for _, query := range data {
					writer.WriteQuery(query)
				}
			}
			condition.L.Unlock()
			waitGroup.Done()
		}(testQueries)
	}

	// wait when all goroutines ready to start before sending broadcast signal
	for i := 0; i < goroutineCount; i++ {
		select {
		case <-run:
			break
		case <-time.NewTimer(time.Millisecond * 500).C:
			t.Fatal("Time out of waiting goroutine start")
		}
	}
	condition.L.Lock()
	condition.Broadcast()
	condition.L.Unlock()

	// wait when all goroutines finished or timeout
	waitFinished := make(chan struct{})
	go func() {
		waitGroup.Wait()
		waitFinished <- struct{}{}
	}()
	select {
	case <-waitFinished:
		break
	case <-time.NewTimer(time.Second * 5).C:
		t.Fatal("Timeout of waiting background goroutines")
	}

	if writer.skippedQueryCount > 0 {
		t.Fatal("Detected unexpected skipping queries")
	}
	waitQueryProcessing(3, writer, t)
	// wait when background goroutine dump all queries to the file
	time.Sleep(sleepTime)

	result, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(result), "\n")
	// we don't sum goroutine count because should be written only unique queries
	expectedCount := len(testQueries) // +1 empty line
	if len(lines) != expectedCount {
		t.Log(lines)
		t.Fatalf("Incorrect amount of queries, %v != %v\n", len(lines), expectedCount)
	}
	if lines[len(lines)-1] != "" {
		t.Fatal("Incorrect last line")
	}
}

func waitQueryProcessing(expectedCount int, writer *QueryWriter, t testing.TB) {
	timeout := time.NewTimer(time.Second * 5)
	for {
		select {
		case <-timeout.C:
			t.Fatal("Haven't waited expected amount of queries")
		default:
			break
		}
		if len(writer.GetQueries()) == expectedCount {
			return
		}
		// give some time to process channel
		time.Sleep(sleepTime)
	}
}

func rawStrings(input []*QueryInfo) []string {
	var result []string
	for _, queryInfo := range input {
		result = append(result, queryInfo.RawQuery)
	}
	return result
}
