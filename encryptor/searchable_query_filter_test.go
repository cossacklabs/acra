package encryptor

import (
	"testing"

	"github.com/cossacklabs/acra/encryptor/config"
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
      - column: specified_client_id
        client_id: specified_client_id
`
	schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(configStr), config.UseMySQL)
	if err != nil {
		t.Fatalf("Can't parse config: %s", err.Error())
	}

	query := `SELECT * from SomeTableInUpperCase WHERE default_client_id = 'value'`

	stmt, err := sqlparser.ParseWithDialect(postgresql.NewPostgreSQLDialect(), query)
	if err != nil {
		t.Fatalf("Can't parse query statement: %s", err.Error())
	}

	selectQuery := stmt.(*sqlparser.Select)
	columnInfo, err := findColumnInfo(selectQuery.From, selectQuery.Where.Expr.(*sqlparser.ComparisonExpr).Left.(*sqlparser.ColName), schemaStore)
	if err != nil {
		t.Fatalf("Can't find column info: %s", err.Error())
	}

	searchableQueryFilter := SearchableQueryFilter{
		schemaStore: schemaStore,
	}

	schemaTable := searchableQueryFilter.getColumnSetting(&sqlparser.ColName{
		Name: sqlparser.NewColIdent("default_client_id"),
	}, columnInfo)

	if schemaTable == nil {
		t.Fatalf("Expect not nil schemaTable, matched with config")
	}
}

func Test_getColumnEqualComparisonExprs_NotColumnComparisonQueries(t *testing.T) {
	searchableQueryFilter := SearchableQueryFilter{}

	queries := []string{
		`select * from mytable where substring(name, 1, 33) = '\x7F08FFD5012B0A7659EABE5758009178A2713749B1200C0BFD505B02D4FA26B08F';`,
		`select * from mytable where encode('é', 'hex') = 'c3a9'`,
	}

	parser := sqlparser.New(sqlparser.ModeStrict)

	for _, query := range queries {
		statement, err := parser.Parse(query)
		if err != nil {
			t.Fatal(err)
		}

		whereStatements, err := getWhereStatements(statement)
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
