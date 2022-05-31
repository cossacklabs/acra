package encryptor

import (
	"github.com/cossacklabs/acra/decryptor/base/mocks"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestGetFirstTableWithoutAlias(t *testing.T) {
	type testcase struct {
		SQL   string
		Table string
		Error error
	}
	testcases := []testcase{
		{SQL: `select * from table1, table2 t2`, Table: "table1"},
		{SQL: `select * from table2 t2, table1`, Table: "table1"},
		{SQL: `select * from table2 t2, table1, table3 as t3`, Table: "table1"},
		{SQL: `select * from table2 t2, table1 t1, table3 as t3`, Error: errNotFoundtable},
		{SQL: `select * from table1 join table2 join table3 join table4`, Table: "table1"},
		{SQL: `select * from table1 t2 join table2 `, Error: errNotFoundtable},
	}

	parser := sqlparser.New(sqlparser.ModeStrict)
	for _, tcase := range testcases {
		parsed, err := parser.Parse(tcase.SQL)
		if err != nil {
			t.Fatal(err)
		}
		selectExpr, ok := parsed.(*sqlparser.Select)
		if !ok {
			t.Fatal("Test cases should contain only Select queries")
		}
		tableName, err := getFirstTableWithoutAlias(selectExpr.From)
		if err != tcase.Error {
			t.Fatal(err)
		}
		// if expected error then we don't need to compare table name
		if tcase.Error != nil {
			continue
		}
		if tableName != tcase.Table {
			t.Fatal("Parsed incorrect table name without alias")
		}
	}
}

func TestMapColumnsToAliases(t *testing.T) {
	parser := sqlparser.New(sqlparser.ModeStrict)
	t.Run("With enumeration fields query", func(t *testing.T) {
		query := `
select t1.col1, t1.col2, t2.col1, t2.col2, t3.col1, t4.col4, col5, table6.col6
from table5, table6
inner join (select col1, col22 as col2, col3 from table1) as t1
inner join (select t1.col1, t2.col3 col2, t1.col3 from table1 t1 inner join table2 t2 on t1.col1=t2.col1) as t2 on t2.col1=t1.col1
inner join table3 t3 on t3.col1=t1.col1
inner join table4 as t4 on t4.col4=t1.col4
inner join table6 on table6.col1=t1.col1
`
		expectedValues := []columnInfo{
			// column's alias is subquery alias with column and table without aliases in subquery
			{Alias: "t1", Table: "table1", Name: "col1"},
			// column's alias is subquery alias with column with AS expression and table without alias
			{Alias: "t1", Table: "table1", Name: "col22"},
			// column's alias is subquery alias and column name has alias in subquery to table with alias
			{Alias: "t2", Table: "table1", Name: "col1"},
			// column's alias is subquery alias and column name has alias in subquery to joined table with alias
			{Alias: "t2", Table: "table2", Name: "col3"},
			// column's alias is alias of joined table
			{Alias: "t3", Table: "table3", Name: "col1"},
			// column's alias is alias of joined table with AS expression
			{Alias: "t4", Table: "table4", Name: "col4"},
			// column without alias of table in FROM expression
			{Table: "table5", Name: "col5", Alias: "table5"},
			// column with alias as table name in FROM expression
			{Table: "table6", Name: "col6", Alias: "table6"},
		}
		parsed, err := parser.Parse(query)
		if err != nil {
			t.Fatal(err)
		}
		selectExpr, ok := parsed.(*sqlparser.Select)
		if !ok {
			t.Fatal("Test query should be Select expression")
		}
		columns, err := mapColumnsToAliases(selectExpr)
		if err != nil {
			t.Fatal(err)
		}
		if len(columns) != len(expectedValues) {
			t.Fatal("Returned incorrect length of values")
		}

		for i, column := range columns {
			if column == nil {
				t.Fatalf("[%d] Column info not found", i)
			}

			if *column != expectedValues[i] {
				t.Fatalf("[%d] Column info is not equal to expected - %+v, actual - %+v", i, expectedValues[i], *column)
			}
		}
	})
	t.Run("Join enumeration fields query", func(t *testing.T) {
		queries := []string{
			`select table1.number, from_number, to_number, type, amount, created_date
			from table1 join table2 as t2 on from_number = t2.number or to_number = t2.number join users as u on t2.user_id = u.id`,

			`select t1.number AS t1_number, t2.number AS t2_number from (select * from tablex) AS t JOIN (table1 AS t1 JOIN table2 AS t2 ON t1.id = t2.exam_type_id) ON t.version_id =
			               t1.version_id`,

			`select t1.number AS t1_number, t2.number, t3.number, t4.number from (select * from tablex) AS t JOIN (table1 AS t1 JOIN table2 AS t2 ON t1.id = t2.exam_type_id)  ON t.version_id =
			              t1.version_id JOIN (table3 AS t3 JOIN table4 AS t4 ON t3.id = t4.exam_type_id) ON t.version_id =
			              t3.version_id`,

			`select t1.number AS t1_number, t2.number, t3.number, t4.number from (select * from tablex) AS t JOIN (table1 AS t1 JOIN table2 AS t2 JOIN table3 as t3 JOIN table4 as t4 ON t1.id = t2.exam_type_id)  ON t.version_id =
			               t1.version_id`,
		}

		expectedValues := [][]columnInfo{
			{
				{Alias: "table1", Table: "table1", Name: "number"},
				{Alias: "table1", Table: "table1", Name: "from_number"},
				{Alias: "table1", Table: "table1", Name: "to_number"},
				{Alias: "table1", Table: "table1", Name: "type"},
				{Alias: "table1", Table: "table1", Name: "amount"},
				{Alias: "table1", Table: "table1", Name: "created_date"},
			},
			{
				{Alias: "t1", Table: "table1", Name: "number"},
				{Alias: "t2", Table: "table2", Name: "number"},
			},
			{
				{Alias: "t1", Table: "table1", Name: "number"},
				{Alias: "t2", Table: "table2", Name: "number"},
				{Alias: "t3", Table: "table3", Name: "number"},
				{Alias: "t4", Table: "table4", Name: "number"},
			},
			{
				{Alias: "t1", Table: "table1", Name: "number"},
				{Alias: "t2", Table: "table2", Name: "number"},
				{Alias: "t3", Table: "table3", Name: "number"},
				{Alias: "t4", Table: "table4", Name: "number"},
			},
		}

		for i, query := range queries {
			parsed, err := parser.Parse(query)
			if err != nil {
				t.Fatal(err)
			}
			selectExpr, ok := parsed.(*sqlparser.Select)
			if !ok {
				t.Fatal("Test query should be Select expression")
			}

			columns, err := mapColumnsToAliases(selectExpr)
			if err != nil {
				t.Fatal(err)
			}

			if len(columns) != len(expectedValues[i]) {
				t.Fatal("Returned incorrect length of values")
			}

			for c, column := range columns {
				if column == nil {
					t.Fatalf("[%d] Column info not found", i)
				}

				if *column != expectedValues[i][c] {
					t.Fatalf("[%d] Column info is not equal to expected - %+v, actual - %+v", i, expectedValues[i][c], *column)
				}
			}
		}
	})
	t.Run("Join enumeration asterisk query", func(t *testing.T) {
		queries := []string{
			`select *  from  test_table join test_table2 join test_table3 t3 on t2.id = t3.id join test_table4 t4 on t3.id = t4.id`,
			`select t2.*, t3.*  from  test_table join test_table2 t2 join test_table3 t3 on t2.id = t3.id join test_table4 t4 on t3.id = t4.id`,
			`select t2.*, t3.*, *  from  test_table join test_table2 t2 join test_table3 t3 on t2.id = t3.id join test_table4 t4 on t3.id = t4.id`,
		}

		expectedValues := [][]columnInfo{
			{
				{Alias: allColumnsName, Table: "test_table", Name: allColumnsName},
				{Alias: allColumnsName, Table: "test_table2", Name: allColumnsName},
				{Alias: allColumnsName, Table: "test_table3", Name: allColumnsName},
				{Alias: allColumnsName, Table: "test_table4", Name: allColumnsName},
			},
			{
				{Alias: allColumnsName, Table: "test_table2", Name: allColumnsName},
				{Alias: allColumnsName, Table: "test_table3", Name: allColumnsName},
			},
			{
				{Alias: allColumnsName, Table: "test_table2", Name: allColumnsName},
				{Alias: allColumnsName, Table: "test_table3", Name: allColumnsName},
				{Alias: allColumnsName, Table: "test_table", Name: allColumnsName},
				{Alias: allColumnsName, Table: "test_table2", Name: allColumnsName},
				{Alias: allColumnsName, Table: "test_table3", Name: allColumnsName},
				{Alias: allColumnsName, Table: "test_table4", Name: allColumnsName},
			},
		}

		for i, query := range queries {
			parsed, err := parser.Parse(query)
			if err != nil {
				t.Fatal(err)
			}
			selectExpr, ok := parsed.(*sqlparser.Select)
			if !ok {
				t.Fatal("Test query should be Select expression")
			}

			columns, err := mapColumnsToAliases(selectExpr)
			if err != nil {
				t.Fatal(err)
			}

			if len(columns) != len(expectedValues[i]) {
				t.Fatal("Returned incorrect length of values")
			}

			for c, column := range columns {
				if column == nil {
					t.Fatalf("[%d] Column info not found", i)
				}

				if *column != expectedValues[i][c] {
					t.Fatalf("[%d] Column info is not equal to expected - %+v, actual - %+v", i, expectedValues[i][c], *column)
				}
			}
		}
	})

	t.Run("With asterisk query", func(t *testing.T) {
		query := `select * from test_table`

		parsed, err := parser.Parse(query)
		if err != nil {
			t.Fatal(err)
		}
		selectExpr, ok := parsed.(*sqlparser.Select)
		if !ok {
			t.Fatal("Test query should be Select expression")
		}

		expectedValue := columnInfo{Alias: "*", Table: "test_table", Name: "*"}

		columns, err := mapColumnsToAliases(selectExpr)
		if err != nil {
			t.Fatal(err)
		}

		if len(columns) != 1 {
			t.Fatal("Returned incorrect length of values")
		}

		column := columns[0]

		if column == nil {
			t.Fatal("Column info not found")
		}

		if *column != expectedValue {
			t.Fatalf("Column info is not equal to expected - %+v, actual - %+v", expectedValue, *column)
		}
	})

	t.Run("Asterisk query with subQuery", func(t *testing.T) {
		queries := []string{
			`select (select value from table2), (select value from table3), * from table1;`,
		}

		// TODO: consider tracking queries with asterisk from sub-queries as we need to map it via encryptor config
		// e.g select anon.value_table1, anon.value_table2 from (select * from table1 as tb1 JOIN table2 AS tb2 ON tb1.id = tb2.id) as anon;

		expectedValues := [][]columnInfo{
			{
				{Alias: "table2", Table: "table2", Name: "value"},
				{Alias: "table3", Table: "table3", Name: "value"},
				{Alias: allColumnsName, Table: "table1", Name: allColumnsName},
			},
		}

		for i, query := range queries {
			parsed, err := parser.Parse(query)
			if err != nil {
				t.Fatal(err)
			}
			selectExpr, ok := parsed.(*sqlparser.Select)
			if !ok {
				t.Fatal("Test query should be Select expression")
			}

			columns, err := mapColumnsToAliases(selectExpr)
			if err != nil {
				t.Fatal(err)
			}

			if len(columns) != len(expectedValues[i]) {
				t.Fatal("Returned incorrect length of values")
			}

			for c, column := range columns {
				if column == nil {
					t.Fatalf("[%d] Column info not found", i)
				}

				if *column != expectedValues[i][c] {
					t.Fatalf("[%d] Column info is not equal to expected - %+v, actual - %+v", i, expectedValues[i][c], *column)
				}
			}
		}
	})

	t.Run("With table asterisk query", func(t *testing.T) {
		query := `select t1.*, t2.* from test_table t1, test_table t2`

		parsed, err := parser.Parse(query)
		if err != nil {
			t.Fatal(err)
		}
		selectExpr, ok := parsed.(*sqlparser.Select)
		if !ok {
			t.Fatal("Test query should be Select expression")
		}

		expectedValue := []columnInfo{
			{Alias: allColumnsName, Table: "test_table", Name: allColumnsName},
			{Alias: allColumnsName, Table: "test_table", Name: allColumnsName},
		}

		columns, err := mapColumnsToAliases(selectExpr)
		if err != nil {
			t.Fatal(err)
		}

		if len(columns) != len(expectedValue) {
			t.Fatal("Returned incorrect length of values")
		}

		for i, expectedColumn := range expectedValue {
			if columns[i].Name != expectedColumn.Name || columns[i].Alias != expectedColumn.Alias || columns[i].Table != expectedColumn.Table {
				t.Fatalf("Column info is not equal to expected - %+v, actual - %+v", expectedValue, columns[i])
			}
		}
	})
}

func TestPlaceholderSettings(t *testing.T) {
	clientSession := &mocks.ClientSession{}
	sessionData := make(map[string]interface{}, 2)
	clientSession.On("GetData", mock.Anything).Return(func(key string) interface{} {
		return sessionData[key]
	}, func(key string) bool {
		_, ok := sessionData[key]
		return ok
	})
	clientSession.On("DeleteData", mock.Anything).Run(func(args mock.Arguments) {
		delete(sessionData, args[0].(string))
	})
	clientSession.On("SetData", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		sessionData[args[0].(string)] = args[1]
	})

	sessionData[placeholdersSettingKey] = "trash"

	data := PlaceholderSettingsFromClientSession(clientSession)
	if data != nil {
		t.Fatal("Expect nil for value with invalid type")
	}
	DeletePlaceholderSettingsFromClientSession(clientSession)

	// get new initialized map
	data = PlaceholderSettingsFromClientSession(clientSession)
	// set some data
	data[0] = &config.BasicColumnEncryptionSetting{}
	data[1] = &config.BasicColumnEncryptionSetting{}

	newData := PlaceholderSettingsFromClientSession(clientSession)
	if len(newData) != len(data) {
		t.Fatal("Unexpected map with different size")
	}
	// clear data, force to return map to the pool cleared from data
	DeletePlaceholderSettingsFromClientSession(clientSession)

	// we expect that will be returned same value from sync.Pool and check that it's cleared
	newData = PlaceholderSettingsFromClientSession(clientSession)
	if len(newData) != 0 {
		t.Fatal("Map's data wasn't cleared")
	}
	if len(newData) != len(data) {
		t.Fatal("Source map's data wasn't cleared")
	}
}
