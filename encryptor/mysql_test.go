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
	"github.com/cossacklabs/acra/acra-writer"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/xwb1989/sqlparser"
	"testing"
)

type testEncryptor struct {
	value      []byte
	fetchedIDs [][]byte
}

func (e *testEncryptor) EncryptWithZoneID(zoneIDdata, data []byte) ([]byte, error) {
	e.fetchedIDs = append(e.fetchedIDs, zoneIDdata)
	return e.value, nil
}
func (e *testEncryptor) reset() {
	e.fetchedIDs = [][]byte{}
}

func (e *testEncryptor) EncryptWithClientID(clientID, data []byte) ([]byte, error) {
	e.fetchedIDs = append(e.fetchedIDs, clientID)
	return e.value, nil
}

// normalizeQuery convert to lower case parts that case-insensitive
func normalizeQuery(query string, t *testing.T) string {
	parsed, err := sqlparser.Parse(query)
	if err != nil {
		t.Fatalf("Can't normalize query: %s - %s", err.Error(), query)
	}
	return sqlparser.String(parsed)
}

func TestMysqlQueryParser_Parse(t *testing.T) {
	zoneID := zone.GenerateZoneID()
	zoneIDStr := string(zoneID)
	clientIDStr := "specified_client_id"
	specifiedClientID := []byte(clientIDStr)
	defaultClientIDStr := "default_client_id"
	defaultClientID := []byte(defaultClientIDStr)

	keypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		t.Fatal(err)
	}
	acrastruct, err := acrawriter.CreateAcrastruct([]byte("some data"), keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	hexAcrastruct := hex.EncodeToString(acrastruct)

	config := fmt.Sprintf(`
schemas:
  - table: TableWithColumnSchema
    columns: ["other_column", "default_client_id", "specified_client_id", "zone_id"]
    encrypted: 
      - name: "default_client_id"
      - name: specified_client_id
        client_id: %s
      - name: zone_id
        zone_id: %s

  - table: TableWithoutColumnSchema
    encrypted: 
      - name: "default_client_id"
      - name: specified_client_id
        client_id: %s
      - name: zone_id
        zone_id: %s
`, clientIDStr, zoneIDStr, clientIDStr, zoneIDStr)
	schemaStore, err := MapTableSchemaStoreFromConfig([]byte(config))
	if err != nil {
		t.Fatalf("Can't parse config: %s", err.Error())
	}
	encryptedValue := []byte("encrypted")
	hexEncryptedValue := hex.EncodeToString(encryptedValue)
	dataValue := "some data"
	dataHexValue := hex.EncodeToString([]byte(dataValue))
	t.Logf("value - %s\nencrypted - %s", dataHexValue, hexEncryptedValue)
	testData := []struct {
		Query             string
		QueryData         []interface{}
		Normalized        bool
		ExpectedQueryData []interface{}
		Changed           bool
		ExpectedIDS       [][]byte
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
	}
	encryptor := &testEncryptor{value: encryptedValue}
	mysqlParser, err := NewMysqlQueryEncryptor(schemaStore, defaultClientID, encryptor)
	if err != nil {
		t.Fatal(err)
	}

	for i, testCase := range testData {
		encryptor.reset()
		query := fmt.Sprintf(testCase.Query, testCase.QueryData...)
		expectedQuery := fmt.Sprintf(testCase.Query, testCase.ExpectedQueryData...)
		if testCase.Normalized {
			expectedQuery = normalizeQuery(expectedQuery, t)
		}
		data, changed, err := mysqlParser.OnQuery(query)
		if err != nil {
			t.Fatalf("%v. %s", i, err.Error())
		}
		if data != expectedQuery {
			t.Fatalf("%v. Incorrect value\nTook:\n%s\nExpected:\n%s;", i, data, expectedQuery)
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
}
