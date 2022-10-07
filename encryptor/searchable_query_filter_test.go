package encryptor

import (
	"fmt"
	"testing"

	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/sqlparser"
)

func TestGetTableSchemaOfColumnMatchConfiTable(t *testing.T) {
	tableName := "some_table"
	configStr := fmt.Sprintf(`
schemas:
  - table: %s
    encrypted: 
      - column: "default_client_id"
      - column: specified_client_id
        client_id: specified_client_id
`, tableName)
	schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(configStr))
	if err != nil {
		t.Fatalf("Can't parse config: %s", err.Error())
	}

	searchableQueryFilter := SearchableQueryFilter{
		schemaStore: schemaStore,
	}

	tableNamesWithQuotes := sqlparser.NewTableIdentWithQuotes(tableName, '"')
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
	tableName := "some_table"
	configStr := fmt.Sprintf(`
schemas:
  - table: %s
    encrypted: 
      - column: "default_client_id"
      - column: specified_client_id
        client_id: specified_client_id
`, tableName)
	schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(configStr))
	if err != nil {
		t.Fatalf("Can't parse config: %s", err.Error())
	}

	searchableQueryFilter := SearchableQueryFilter{
		schemaStore: schemaStore,
	}

	tableNamesWithQuotes := sqlparser.NewTableIdentWithQuotes(tableName, '"')

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
