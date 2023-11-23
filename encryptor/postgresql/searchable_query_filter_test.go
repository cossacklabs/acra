package postgresql

import (
	"testing"

	pg_query "github.com/Zhaars/pg_query_go/v4"

	"github.com/cossacklabs/acra/encryptor/base/config"
)

func TestGetTableSchemaOfColumnMatchConfigTable(t *testing.T) {
	configStr := `
schemas:
  - table: sometableinuppercase
    columns:
      - default_client_id
      - specified_client_id
    encrypted: 
      - column: "default_client_id"
        searchable: true
      - column: specified_client_id
        client_id: specified_client_id
        searchable: true
`
	schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(configStr), config.UseMySQL)
	if err != nil {
		t.Fatalf("Can't parse config: %s", err.Error())
	}

	queries := []string{
		`SELECT * from SomeTableInUpperCase WHERE default_client_id = 'value'`,
		`SELECT * from SomeTableInUpperCase WHERE substr(default_client_id, 1, 33) = 'value'`,
	}

	for _, query := range queries {
		stmt, err := pg_query.Parse(query)
		if err != nil {
			t.Fatalf("Can't parse query statement: %s", err.Error())
		}

		selectStmt := stmt.Stmts[0].Stmt.GetSelectStmt()

		expr := selectStmt.GetWhereClause().GetAExpr()
		if expr == nil {
			t.Fatalf("Can't parse where statement: %s", err.Error())
		}

		var lColumn = expr.Lexpr.GetColumnRef()
		if expr.Lexpr.GetColumnRef() == nil {
			//handle case if query was processed by searchable encryptor
			if funcCall := expr.Lexpr.GetFuncCall(); funcCall != nil {
				funcName := funcCall.GetFuncname()
				if len(funcName) == 1 && funcName[0].GetString_().GetSval() == "substr" {
					lColumn = funcCall.GetArgs()[0].GetColumnRef()
				}
			}
		}

		columnInfo, err := FindColumnInfo(selectStmt.FromClause, lColumn, schemaStore)
		if err != nil {
			t.Fatalf("Can't find column info: %s", err.Error())
		}

		schemaTable := GetColumnSetting(lColumn, columnInfo.Table, schemaStore)
		if schemaTable == nil {
			t.Fatalf("Expect not nil schemaTable, matched with config")
		}
	}
}

func Test_getColumnEqualComparisonExprs_NotColumnComparisonQueries(t *testing.T) {
	configStr := `
schemas:
 - table: mytable
   columns:
     - name
   encrypted:
     - column: "name"
       searchable: true
`
	schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(configStr), config.UseMySQL)
	if err != nil {
		t.Fatalf("Can't parse config: %s", err.Error())
	}
	searchableQueryFilter := SearchableQueryFilter{schemaStore: schemaStore}

	queries := []string{
		`select * from mytable where substring(not_searchable, 1, 33) = '\x7F08FFD5012B0A7659EABE5758009178A2713749B1200C0BFD505B02D4FA26B08F';`,
		`select * from mytable where encode('é', 'hex') = 'c3a9'`,
	}

	for _, query := range queries {
		stmt, err := pg_query.Parse(query)
		if err != nil {
			t.Fatalf("Can't parse query statement: %s", err.Error())
		}

		selectStmt := stmt.Stmts[0].Stmt.GetSelectStmt()

		whereStatements, err := GetWhereStatements(stmt)
		if err != nil {
			t.Fatalf("expected no error on parsing valid WHERE clause query - %s", err.Error())
		}

		compExprs, err := searchableQueryFilter.filterColumnEqualComparisonExprs(whereStatements[0], selectStmt.FromClause)
		if err != nil {
			t.Fatal(err)
		}

		if compExprs != nil {
			t.Fatalf("expected nil compExprs")
		}
	}
}
