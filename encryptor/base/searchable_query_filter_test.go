package base

import (
	"testing"

	"github.com/cossacklabs/acra/encryptor/base/config"

	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/sqlparser/dialect/postgresql"
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
		stmt, err := sqlparser.ParseWithDialect(postgresql.NewPostgreSQLDialect(), query)
		if err != nil {
			t.Fatalf("Can't parse query statement: %s", err.Error())
		}

		selectQuery := stmt.(*sqlparser.Select)
		leftExpr := selectQuery.Where.Expr.(*sqlparser.ComparisonExpr).Left
		var columnInfo ColumnInfo
		switch val := leftExpr.(type) {
		case *sqlparser.ColName:
			columnInfo, err = FindColumnInfo(selectQuery.From, val, schemaStore)
		case *sqlparser.SubstrExpr:
			columnInfo, err = FindColumnInfo(selectQuery.From, val.Name, schemaStore)
		default:
			t.Fatal("Unexpected type of expr")
		}
		if err != nil {
			t.Fatalf("Can't find column info: %s", err.Error())
		}

		schemaTable := GetColumnSetting(&sqlparser.ColName{
			Name: sqlparser.NewColIdent("default_client_id"),
		}, columnInfo.Table, schemaStore)

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

	parser := sqlparser.New(sqlparser.ModeStrict)

	for _, query := range queries {
		statement, err := parser.Parse(query)
		if err != nil {
			t.Fatal(err)
		}

		whereStatements, err := GetWhereStatements(statement)
		if err != nil {
			t.Fatalf("expected no error on parsing valid WHERE clause query - %s", err.Error())
		}

		compExprs, err := searchableQueryFilter.filterColumnEqualComparisonExprs(whereStatements[0], statement.(*sqlparser.Select).From)
		if err != nil {
			t.Fatal(err)
		}

		if compExprs != nil {
			t.Fatalf("expected nil compExprs")
		}
	}
}
