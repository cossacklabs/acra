package encryptor

import (
	"testing"

	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/sqlparser"
)

func TestGetTableSchemaOfColumnMatchConfigTable(t *testing.T) {
	tableNameUpperCase := "SomeTableInUpperCase"
	configStr := `
schemas:
  - table: sometableinuppercase
    encrypted: 
      - column: "default_client_id"
      - column: specified_client_id
        client_id: specified_client_id
`
	schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(configStr), config.UseMySQL)
	if err != nil {
		t.Fatalf("Can't parse config: %s", err.Error())
	}

	searchableQueryFilter := SearchableQueryFilter{
		schemaStore: schemaStore,
	}

	tableNamesWithQuotes := sqlparser.NewTableIdentWithQuotes(tableNameUpperCase, '"')
	schemaTable := searchableQueryFilter.getTableSchemaOfColumn(&sqlparser.ColName{}, &AliasedTableName{
		TableName: sqlparser.TableName{
			Name: tableNamesWithQuotes,
		},
	}, AliasToTableMap{})

	if schemaTable == nil {
		t.Fatalf("Expect not nil schemaTable, matched with config")
	}
}

func TestFilterInterestingTables(t *testing.T) {
	tableNameUpperCase := "SomeTableInUpperCase"
	configStr := `
schemas:
  - table: sometableinuppercase
    encrypted: 
      - column: "default_client_id"
      - column: specified_client_id
        client_id: specified_client_id
`
	schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(configStr), config.UseMySQL)
	if err != nil {
		t.Fatalf("Can't parse config: %s", err.Error())
	}

	searchableQueryFilter := SearchableQueryFilter{
		schemaStore: schemaStore,
	}

	tableNamesWithQuotes := sqlparser.NewTableIdentWithQuotes(tableNameUpperCase, '"')

	aliasedTable, _ := searchableQueryFilter.filterInterestingTables(sqlparser.TableExprs{
		&sqlparser.AliasedTableExpr{
			Expr: sqlparser.TableName{
				Name: tableNamesWithQuotes,
			},
		},
	})

	if aliasedTable == nil {
		t.Fatalf("Expect not nil aliasedTable, matched with config")
	}
}
