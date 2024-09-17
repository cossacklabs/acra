package postgresql

import (
	"testing"

	pg_query "github.com/cossacklabs/pg_query_go/v5"

	"github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
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
		{SQL: `select * from table1 join table2 t2 on t1.test = test join table3 t3 on t2.test = t3.test join table4 t4 on t3.test = t4.test`, Table: "table1"},
		{SQL: `select * from table1 t2 join table2 t3 on t2.test = t3.test `, Error: errNotFoundtable},
	}

	for _, tcase := range testcases {
		parsed, err := pg_query.Parse(tcase.SQL)
		if err != nil {
			t.Fatal(err)
		}

		tableName, err := getFirstTableWithoutAlias(parsed.Stmts[0].GetStmt().GetSelectStmt().FromClause)
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
	t.Run("With enumeration fields query", func(t *testing.T) {

		testConfig := `
schemas:
  - table: table5
    columns:
      - col5
    encrypted:
      - column: col5

  - table: table6
    columns:
      - col6
    encrypted:
      - column: col6
`
		schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(testConfig), config.UseMySQL)
		if err != nil {
			t.Fatal(err)
		}

		query := `
select t1.col1,
       t1.col2,
       t2.col1,
       t2.col2,
       t3.col1,
       t4.col4,
       col5,
       table6.col6
from table5,
     table6
         inner join (select col1, col22 as col2, col3 from table1) as t1 on t2.col1 = t1.col1
         inner join (select t1.col1, t2.col3 col2, t1.col3
                     from table1 t1
                              inner join table2 t2 on t1.col1 = t2.col1) as t2 on t2.col1 = t1.col1
         inner join table3 t3 on t3.col1 = t1.col1
         inner join table4 as t4 on t4.col4 = t1.col4
         inner join table6 on table6.col1 = t1.col1

`
		expectedValues := []base.ColumnInfo{
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

		parsed, err := pg_query.Parse(query)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := MapColumnsToAliases(parsed.Stmts[0].GetStmt().GetSelectStmt(), schemaStore)
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
	t.Run("with aliased table and non-aliased colum name", func(t *testing.T) {
		testConfig := `
schemas:
  - table: users
    columns:
      - id
      - email
      - mobile_number
    encrypted:
      - column: id

  - table: users_duplicate
    columns:
      - id
      - email
      - mobile_number
    encrypted:
      - column: id

  - table: users_temp
    columns:
      - id_tmp
      - email_tmp
      - mobile_number_tmp
    encrypted:
      - column: id_tmp
`
		schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(testConfig), config.UseMySQL)
		if err != nil {
			t.Fatal(err)
		}

		testcases := []struct {
			query          string
			expectedValues []*base.ColumnInfo
		}{
			{
				query: `SELECT "id", "email", "mobile_number" AS "mobileNumber" FROM "users" AS "User" where "User"."is_active"`,
				expectedValues: []*base.ColumnInfo{
					{Alias: "User", Table: "users", Name: "id"},
					{Alias: "User", Table: "users", Name: "email"},
					{Alias: "User", Table: "users", Name: "mobile_number"},
				},
			},
			{
				query: `SELECT "id", "email", "mobile_number" AS "mobileNumber" FROM "users" AS "User", "table1" as "test_table"`,
				expectedValues: []*base.ColumnInfo{
					{Alias: "User", Table: "users", Name: "id"},
					{Alias: "User", Table: "users", Name: "email"},
					{Alias: "User", Table: "users", Name: "mobile_number"},
				},
			},
			{
				query: `SELECT "id", "email", "mobile_number" AS "mobileNumber" FROM "users" AS "User", "users_duplicate" as "User2"`,
				expectedValues: []*base.ColumnInfo{
					nil, nil, nil,
				},
			},
			{
				query: `SELECT "id", "email", "mobile_number", "id_tmp", "email_tmp", "mobile_number_tmp"  AS "mobileNumber" FROM "users" AS "User", "users_temp" as "temp"`,
				expectedValues: []*base.ColumnInfo{
					{Alias: "User", Table: "users", Name: "id"},
					{Alias: "User", Table: "users", Name: "email"},
					{Alias: "User", Table: "users", Name: "mobile_number"},
					{Alias: "temp", Table: "users_temp", Name: "id_tmp"},
					{Alias: "temp", Table: "users_temp", Name: "email_tmp"},
					{Alias: "temp", Table: "users_temp", Name: "mobile_number_tmp"},
				},
			},
		}
		for i, tcase := range testcases {
			parsed, err := pg_query.Parse(tcase.query)
			if err != nil {
				t.Fatal(err)
			}

			columns, err := MapColumnsToAliases(parsed.Stmts[0].GetStmt().GetSelectStmt(), schemaStore)
			if err != nil {
				t.Fatal(err)
			}
			if len(columns) != len(tcase.expectedValues) {
				t.Fatal("Returned incorrect length of values")
			}

			for y, column := range columns {
				if column == nil {
					if tcase.expectedValues[y] != nil {
						t.Fatalf("[%d] expected nil column value ", i)
					}
					continue
				}

				if *column != *tcase.expectedValues[y] {
					t.Fatalf("[%d] Column info is not equal to expected - %+v, actual - %+v", i, tcase.expectedValues[i], *column)
				}
			}
		}
	})
	t.Run("Join enumeration fields query", func(t *testing.T) {
		queries := []string{
			`select table1.number, from_number, to_number, type, amount, created_date
				from table1 join table2 as t2 on from_number = t2.number or to_number = t2.number join users as u on t2.user_id = u.id`,

			// select with revers order of JOINs declaration
			`select t3.*, t1.*, t2.*
				from table1 AS t1 join table2 as t2 on from_number = t2.number or to_number = t2.number join table3 as t3 on t2.user_id = t3.id`,

			// case with multiple table JOIN block ParenTableExpr
			`select t1.number AS t1_number, t2.number AS t2_number from (select * from tablex) AS t JOIN (table1 AS t1 JOIN table2 AS t2 ON t1.id = t2.exam_type_id) ON t.version_id =
				              t1.version_id`,
			//
			// example with several multiple table JOIN blocks ParenTableExpr
			`select t1.number AS t1_number, t2.number, t3.number, t4.number from (select * from tablex) AS t JOIN (table1 AS t1 JOIN table2 AS t2 ON t1.id = t2.exam_type_id)  ON t.version_id =
				             t1.version_id JOIN (table3 AS t3 JOIN table4 AS t4 ON t3.id = t4.exam_type_id) ON t.version_id =
				             t3.version_id`,
		}

		expectedValues := [][]base.ColumnInfo{
			{
				{Alias: "table1", Table: "table1", Name: "number"},
				{Alias: "table1", Table: "table1", Name: "from_number"},
				{Alias: "table1", Table: "table1", Name: "to_number"},
				{Alias: "table1", Table: "table1", Name: "type"},
				{Alias: "table1", Table: "table1", Name: "amount"},
				{Alias: "table1", Table: "table1", Name: "created_date"},
			},
			{
				{Alias: allColumnsName, Table: "table3", Name: allColumnsName},
				{Alias: allColumnsName, Table: "table1", Name: allColumnsName},
				{Alias: allColumnsName, Table: "table2", Name: allColumnsName},
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
			parsed, err := pg_query.Parse(query)
			if err != nil {
				t.Fatal(err)
			}

			columns, err := MapColumnsToAliases(parsed.Stmts[0].GetStmt().GetSelectStmt(), &config.MapTableSchemaStore{})
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
			`select *  from  test_table join test_table2 t2 on true join test_table3 t3 on t2.id = t3.id join test_table4 t4 on t3.id = t4.id`,
			`select t2.*, t3.*  from  test_table join test_table2 t2 on true join test_table3 t3 on t2.id = t3.id join test_table4 t4 on t3.id = t4.id`,
			`select t2.*, t3.*, *  from  test_table join test_table2 t2 on true join test_table3 t3 on t2.id = t3.id join test_table4 t4 on t3.id = t4.id`,
		}

		expectedValues := [][]base.ColumnInfo{
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
			parsed, err := pg_query.Parse(query)
			if err != nil {
				t.Fatal(err)
			}

			columns, err := MapColumnsToAliases(parsed.Stmts[0].GetStmt().GetSelectStmt(), &config.MapTableSchemaStore{})
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

		parsed, err := pg_query.Parse(query)
		if err != nil {
			t.Fatal(err)
		}

		expectedValue := base.ColumnInfo{Alias: "*", Table: "test_table", Name: "*"}

		columns, err := MapColumnsToAliases(parsed.Stmts[0].GetStmt().GetSelectStmt(), &config.MapTableSchemaStore{})
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
		testConfig := `
schemas:
  - table: table2
    columns:
      - value
    encrypted:
      - column: value

  - table: table3
    columns:
      - value
    encrypted:
      - column: value
`
		schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(testConfig), config.UseMySQL)
		if err != nil {
			t.Fatal(err)
		}

		queries := []string{
			`select (select value from table2), (select value from table3), * from table1;`,
		}

		// TODO: consider tracking queries with asterisk from sub-queries as we need to map it via encryptor config
		// e.g select anon.value_table1, anon.value_table2 from (select * from table1 as tb1 JOIN table2 AS tb2 ON tb1.id = tb2.id) as anon;

		expectedValues := [][]base.ColumnInfo{
			{
				{Alias: "table2", Table: "table2", Name: "value"},
				{Alias: "table3", Table: "table3", Name: "value"},
				{Alias: allColumnsName, Table: "table1", Name: allColumnsName},
			},
		}

		for i, query := range queries {
			parsed, err := pg_query.Parse(query)
			if err != nil {
				t.Fatal(err)
			}

			columns, err := MapColumnsToAliases(parsed.Stmts[0].GetStmt().GetSelectStmt(), schemaStore)
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

		parsed, err := pg_query.Parse(query)
		if err != nil {
			t.Fatal(err)
		}

		expectedValue := []base.ColumnInfo{
			{Alias: allColumnsName, Table: "test_table", Name: allColumnsName},
			{Alias: allColumnsName, Table: "test_table", Name: allColumnsName},
		}

		columns, err := MapColumnsToAliases(parsed.Stmts[0].GetStmt().GetSelectStmt(), &config.MapTableSchemaStore{})
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
