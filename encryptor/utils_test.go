package encryptor

import (
	"github.com/cossacklabs/acra/sqlparser"
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
	}
	for _, tcase := range testcases {
		parsed, err := sqlparser.Parse(tcase.SQL)
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
	parsed, err := sqlparser.Parse(query)
	if err != nil {
		t.Fatal(err)
	}
	selectExpr, ok := parsed.(*sqlparser.Select)
	if !ok {
		t.Fatal("Test query should be Select expression")
	}
	columns := mapColumnsToAliases(selectExpr)
	if len(columns) != len(expectedValues) {
		t.Fatal("Returned incorrect length of values")
	}

	for i, column := range columns {
		if column == nil {
			t.Fatalf("[%d] Column info not found", i)
		}
		if expectedValues[i].Alias != column.Alias {
			t.Fatalf("[%d] Aliases not equal", i)
		}
		if expectedValues[i].Table != column.Table {
			t.Fatalf("[%d] Table names not equal", i)
		}
		if expectedValues[i].Name != column.Name {
			t.Fatalf("[%d] Column names not equal", i)
		}
	}

}
