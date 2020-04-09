/*
Copyright 2018, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package encryptor

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	acrawriter "github.com/cossacklabs/acra/acra-writer"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/sqlparser/dialect"
	"github.com/cossacklabs/acra/sqlparser/dialect/mysql"
	"github.com/cossacklabs/acra/sqlparser/dialect/postgresql"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
)

type testEncryptor struct {
	value      []byte
	fetchedIDs [][]byte
}

func (e *testEncryptor) EncryptWithZoneID(zoneIDdata, data []byte, setting EncryptionSetting) ([]byte, error) {
	if base.ValidateAcraStructLength(data) == nil {
		return data, nil
	}
	e.fetchedIDs = append(e.fetchedIDs, zoneIDdata)
	return e.value, nil
}
func (e *testEncryptor) reset() {
	e.fetchedIDs = [][]byte{}
}

func (e *testEncryptor) EncryptWithClientID(clientID, data []byte, setting EncryptionSetting) ([]byte, error) {
	if base.ValidateAcraStructLength(data) == nil {
		return data, nil
	}
	e.fetchedIDs = append(e.fetchedIDs, clientID)
	return e.value, nil
}

// normalizeQueryWithDialect convert to lower case parts that case-insensitive for specified dialect
func normalizeQueryWithDialect(dialect dialect.Dialect, query string) (string, error) {
	parsed, err := sqlparser.ParseWithDialect(dialect, query)
	if err != nil {
		return "", err
	}
	return sqlparser.StringWithDialect(dialect, parsed), nil
}

func TestGeneralQueryParser_Parse(t *testing.T) {
	zoneID := zone.GenerateZoneID()
	zoneIDStr := string(zoneID)
	clientIDStr := "specified_client_id"
	specifiedClientID := []byte(clientIDStr)
	defaultClientIDStr := "default_client_id"
	defaultClientID := []byte(defaultClientIDStr)

	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	acrastruct, err := acrawriter.CreateAcrastruct([]byte("some data"), keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	hexAcrastruct := hex.EncodeToString(acrastruct)

	configStr := fmt.Sprintf(`
schemas:
  - table: TableWithColumnSchema
    columns: ["other_column", "default_client_id", "specified_client_id", "zone_id"]
    encrypted: 
      - column: "default_client_id"
      - column: specified_client_id
        client_id: %s
      - column: zone_id
        zone_id: %s

  - table: TableWithoutColumnSchema
    encrypted: 
      - column: "default_client_id"
      - column: specified_client_id
        client_id: %s
      - column: zone_id
        zone_id: %s
`, clientIDStr, zoneIDStr, clientIDStr, zoneIDStr)
	schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(configStr))
	if err != nil {
		t.Fatalf("Can't parse config: %s", err.Error())
	}
	simpleStringData := []byte("string data")
	encryptedValue := []byte("encrypted")
	hexEncryptedValue := hex.EncodeToString(encryptedValue)
	dataValue := make([]byte, 256)
	for i := 0; i < 256; i++ {
		dataValue[i] = byte(i)
	}
	dataHexValue := hex.EncodeToString([]byte(dataValue))
	// TODO add test cases with string, binary, int values. First should be decrypted as is, second as hex, third as is
	testData := []struct {
		Query             string
		QueryData         []interface{}
		Normalized        bool
		ExpectedQueryData []interface{}
		Changed           bool
		ExpectedIDS       [][]byte
		DataCoder         DBDataCoder
		dialect           dialect.Dialect
	}{
		// 0. without list of columns and with schema, one value
		{
			Query:             `INSERT INTO TableWithColumnSchema VALUES (1, X'%s', X'%s', X'%s')`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{defaultClientID, specifiedClientID, zoneID},
		},
		// 1. without list of columns and with schema
		{
			Query:             `INSERT INTO TableWithColumnSchema VALUES (1, X'%s', X'%s', X'%s'), (1, X'%s', X'%s', X'%s')`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{hexEncryptedValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{defaultClientID, specifiedClientID, zoneID, defaultClientID, specifiedClientID, zoneID},
		},
		// 2. without list of columns and without schema
		{
			Query:             `INSERT INTO TableWithoutColumnSchema VALUES (1, X'%s', X'%s', X'%s'), (1, X'%s', X'%s', X'%s')`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			Normalized:        false,
			Changed:           false,
			ExpectedIDS:       [][]byte{},
		},
		// 3. with list of columns and without schema
		{
			Query:             `INSERT INTO TableWithoutColumnSchema (zone_id, specified_client_id, other_column, default_client_id) VALUES (X'%s', X'%s', 1, X'%s')`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{zoneID, specifiedClientID, defaultClientID},
		},
		// 4. insert with ON DUPLICATE without columns and with schema
		{
			Query:             `INSERT INTO TableWithColumnSchema VALUES (X'%s', X'%s', X'%s', X'%s'), (1, X'%s', X'%s', X'%s') ON DUPLICATE KEY UPDATE other_column=X'%s', specified_client_id=X'%s', zone_id=X'%s', default_client_id=X'%s';`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue, dataHexValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{defaultClientID, specifiedClientID, zoneID, defaultClientID, specifiedClientID, zoneID, specifiedClientID, zoneID, defaultClientID},
		},
		// 5. insert with ON DUPLICATE without columns and without schema
		{
			Query:             `INSERT INTO TableWithoutColumnSchema VALUES (X'%s', X'%s', X'%s', X'%s') ON DUPLICATE KEY UPDATE other_column=X'%s', specified_client_id=X'%s', zone_id=X'%s', default_client_id=X'%s';`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{specifiedClientID, zoneID, defaultClientID},
		},
		// 6. insert with ON DUPLICATE with columns and without schema
		{
			Query:             `INSERT INTO TableWithoutColumnSchema (zone_id, specified_client_id, other_column, default_client_id) VALUES (X'%s', X'%s', X'%s', X'%s') ON DUPLICATE KEY UPDATE default_client_id=X'%s', other_column=X'%s', specified_client_id=X'%s', zone_id=X'%s';`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{hexEncryptedValue, hexEncryptedValue, dataHexValue, hexEncryptedValue, hexEncryptedValue, dataHexValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{zoneID, specifiedClientID, defaultClientID, defaultClientID, specifiedClientID, zoneID},
		},
		// 7. insert without encryption
		{
			Query:             `INSERT INTO TableWithoutColumnSchema (other_column, other_column) VALUES (X'%s', X'%s') ON DUPLICATE KEY UPDATE other_column=X'%s', other_column=X'%s';`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			Normalized:        false,
			Changed:           false,
			ExpectedIDS:       [][]byte{},
		},
		// 8. insert without table info
		{
			Query:             `INSERT INTO UnknownTable (other_column, specified_client_id, default_client_id, zone_id) VALUES (X'%s', X'%s', X'%s', X'%s') ON DUPLICATE KEY UPDATE other_column=X'%s', other_column=X'%s';`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			Normalized:        false,
			Changed:           false,
			ExpectedIDS:       [][]byte{},
		},
		// 9. update with encryptable and not encryptable column
		{
			Query:             `UPDATE TableWithoutColumnSchema as t set other_column=X'%s', specified_client_id=X'%s', zone_id=X'%s', default_client_id=X'%s'`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{specifiedClientID, zoneID, defaultClientID},
		},
		// 10. update without encryption
		{
			Query:             `UPDATE TableWithoutColumnSchema set other_column=X'%s', other_column=X'%s'`,
			QueryData:         []interface{}{dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, dataHexValue},
			Normalized:        false,
			Changed:           false,
			ExpectedIDS:       [][]byte{},
		},
		// 11. update without table info
		{
			Query:             `UPDATE UnknownTable set other_column=X'%s', other_column=X'%s', specified_client_id=X'%s', default_client_id=X'%s', zone_id=X'%s'`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			Normalized:        false,
			Changed:           false,
			ExpectedIDS:       [][]byte{},
		},
		// 12. aliased update with encryptable and not encryptable column
		{
			Query:             `UPDATE TableWithoutColumnSchema as t set other_column=X'%s', t.specified_client_id=X'%s', t.zone_id=X'%s', default_client_id=X'%s'`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{specifiedClientID, zoneID, defaultClientID},
		},
		// 13. update with two tables with encryptable and not encryptable column
		{
			Query:             `UPDATE TableWithoutColumnSchema, TableWithoutColumnSchema as t2, UnknownTable as un set un.other_column=X'%s', t2.specified_client_id=X'%s', zone_id=X'%s', default_client_id=X'%s'`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{specifiedClientID, zoneID, defaultClientID},
		},
		// 14. insert with subquery and ON DUPLICATE
		{
			Query:             `INSERT INTO TableWithoutColumnSchema (other_column, specified_client_id, default_client_id, zone_id) SELECT * FROM TableWithoutColumnSchema ON DUPLICATE KEY UPDATE other_column=X'%s', specified_client_id=X'%s', zone_id=X'%s', default_client_id=X'%s'`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{specifiedClientID, zoneID, defaultClientID},
		},
		// 15. insert with subquery
		{
			Query:             `INSERT INTO TableWithoutColumnSchema (other_column, specified_client_id, default_client_id, zone_id) SELECT * FROM TableWithoutColumnSchema`,
			QueryData:         []interface{}{},
			ExpectedQueryData: []interface{}{},
			Normalized:        false,
			Changed:           false,
			ExpectedIDS:       [][]byte{},
		},
		// 16. insert with SET expressions
		{
			Query:             `INSERT INTO TableWithoutColumnSchema SET other_column=X'%s', specified_client_id=X'%s', default_client_id=X'%s', zone_id=X'%s'`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID, zoneID},
		},
		// 17. update with join
		{
			Query:             `UPDATE TableWithoutColumnSchema INNER JOIN TableWithoutColumnSchema as t2 on t2.id=TableWithoutColumnSchema.id, (SELECT * FROM UnknownTable) as un set un.other_column=X'%s', t2.specified_client_id=X'%s', zone_id=X'%s', default_client_id=X'%s'`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{specifiedClientID, zoneID, defaultClientID},
		},
		// 18. update with parenthesized tables
		{
			Query:             `UPDATE (TableWithoutColumnSchema, TableWithoutColumnSchema as t2, UnknownTable as un) SET un.other_column=X'%s', t2.specified_client_id=X'%s', zone_id=X'%s', default_client_id=X'%s'`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{specifiedClientID, zoneID, defaultClientID},
		},
		// 19. INSERT with ignorable acrastruct
		{
			Query:             `INSERT INTO TableWithColumnSchema VALUES (1, X'%s', X'%s', X'%s')`,
			QueryData:         []interface{}{hexAcrastruct, hexAcrastruct, dataHexValue},
			ExpectedQueryData: []interface{}{hexAcrastruct, hexAcrastruct, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{zoneID},
		},
		// 20. update ignorable acrastruct
		{
			Query:             `UPDATE TableWithoutColumnSchema as t set other_column=X'%s', specified_client_id=X'%s', zone_id=X'%s', default_client_id=X'%s'`,
			QueryData:         []interface{}{dataHexValue, hexAcrastruct, hexAcrastruct, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, hexAcrastruct, hexAcrastruct, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{defaultClientID},
		},
		// 21. with double quoted table and column names
		{
			Query:             `INSERT INTO "TableWithoutColumnSchema" ("zone_id", "specified_client_id", "other_column", "default_client_id") VALUES (X'%s', X'%s', 1, X'%s')`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{zoneID, specifiedClientID, defaultClientID},
			dialect:           mysql.NewANSIMySQLDialect(),
		},
		// 22. with back quoted table and column names
		{
			Query:             "INSERT INTO `TableWithoutColumnSchema` (`zone_id`, `specified_client_id`, `other_column`, `default_client_id`) VALUES (X'%s', X'%s', 1, X'%s')",
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{zoneID, specifiedClientID, defaultClientID},
		},
		// 23. update with double quoted identifiers
		{
			Query:             `UPDATE "TableWithoutColumnSchema" as "t" set "other_column"=X'%s', "specified_client_id"=X'%s', "zone_id"=X'%s', "default_client_id"=X'%s'`,
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{specifiedClientID, zoneID, defaultClientID},
			dialect:           mysql.NewANSIMySQLDialect(),
		},
		// 24. update with back quoted identifiers
		{
			Query:             "UPDATE `TableWithoutColumnSchema` as `t` set `other_column`=X'%s', `specified_client_id`=X'%s', `zone_id`=X'%s', `default_client_id`=X'%s'",
			QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
			ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{specifiedClientID, zoneID, defaultClientID},
		},
		// 25. insert with data as simple string
		{
			Query:             `INSERT INTO "TableWithoutColumnSchema" ("zone_id", "specified_client_id", "other_column", "default_client_id") VALUES ('%s', '%s', 1, '%s')`,
			QueryData:         []interface{}{simpleStringData, simpleStringData, simpleStringData},
			ExpectedQueryData: []interface{}{encryptedValue, encryptedValue, encryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{zoneID, specifiedClientID, defaultClientID},
			dialect:           mysql.NewANSIMySQLDialect(),
		},
		// 26. update with data as simple string
		{
			Query:             `UPDATE "TableWithoutColumnSchema" as "t" set "other_column"='%s', "specified_client_id"='%s', "zone_id"='%s', "default_client_id"='%s'`,
			QueryData:         []interface{}{simpleStringData, simpleStringData, simpleStringData, simpleStringData},
			ExpectedQueryData: []interface{}{simpleStringData, encryptedValue, encryptedValue, encryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{specifiedClientID, zoneID, defaultClientID},
			dialect:           mysql.NewANSIMySQLDialect(),
		},

		// 27. insert with data as simple string for postgresql
		{
			Query:             `INSERT INTO "TableWithoutColumnSchema" ('zone_id', 'specified_client_id', 'other_column', 'default_client_id') VALUES ('%s', '%s', 1, '%s')`,
			QueryData:         []interface{}{simpleStringData, simpleStringData, simpleStringData},
			ExpectedQueryData: []interface{}{encryptedValue, encryptedValue, encryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{zoneID, specifiedClientID, defaultClientID},
			DataCoder:         &PostgresqlDBDataCoder{},
			dialect:           postgresql.NewPostgreSQLDialect(),
		},
		// 28. update with data as simple string for postgresql
		{
			Query:             `UPDATE "TableWithoutColumnSchema" as "t" set "other_column"='%s', "specified_client_id"='%s', "zone_id"='%s', "default_client_id"='%s'`,
			QueryData:         []interface{}{simpleStringData, simpleStringData, simpleStringData, simpleStringData},
			ExpectedQueryData: []interface{}{simpleStringData, encryptedValue, encryptedValue, encryptedValue},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{specifiedClientID, zoneID, defaultClientID},
			DataCoder:         &PostgresqlDBDataCoder{},
			dialect:           postgresql.NewPostgreSQLDialect(),
		},
	}
	encryptor := &testEncryptor{value: encryptedValue}
	mysqlParser, err := NewMysqlQueryEncryptor(schemaStore, defaultClientID, encryptor)
	if err != nil {
		t.Fatal(err)
	}

	var dialect dialect.Dialect

	for i, testCase := range testData {
		encryptor.reset()
		if testCase.DataCoder != nil {
			mysqlParser.dataCoder = testCase.DataCoder
		}
		dialect = testCase.dialect
		if dialect == nil {
			dialect = mysql.NewMySQLDialect()
		}
		sqlparser.SetDefaultDialect(dialect)
		query := fmt.Sprintf(testCase.Query, testCase.QueryData...)
		expectedQuery := fmt.Sprintf(testCase.Query, testCase.ExpectedQueryData...)
		if testCase.Normalized {
			expectedQuery, err = normalizeQueryWithDialect(dialect, expectedQuery)
			if err != nil {
				t.Fatalf("%v. Can't normalize query: %s - %s", i, err.Error(), query)
			}
		}
		data, changed, err := mysqlParser.OnQuery(base.NewOnQueryObjectFromQuery(query))
		if err != nil {
			t.Fatalf("%v. %s", i, err.Error())
		}
		if data.Query() != expectedQuery {
			t.Fatalf("%v. Incorrect value\nTook:\n%s\nExpected:\n%s;", i, data.Query(), expectedQuery)
		}
		if testCase.Changed != changed {
			t.Fatalf("%v. Incorrect <changed> value. Took - %t; Expected - %t", i, changed, testCase.Changed)
		}
		if len(encryptor.fetchedIDs) != len(testCase.ExpectedIDS) {
			t.Fatalf("%v. Incorrect length of fetched keys id. Took: %v; Expected: %v", i, len(encryptor.fetchedIDs), len(testCase.ExpectedIDS))
		}
		for i := 0; i < len(encryptor.fetchedIDs); i++ {
			if !bytes.Equal(encryptor.fetchedIDs[i], testCase.ExpectedIDS[i]) {
				t.Fatalf("%v. Incorrect fetched id\nTook: %v\nExpected: %v", i, encryptor.fetchedIDs, testCase.ExpectedIDS)
			}
		}
	}
	// avoid side effect for other tests with configuring default dialect
	sqlparser.SetDefaultDialect(mysql.NewMySQLDialect())
}
