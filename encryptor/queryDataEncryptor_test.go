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
	"context"
	"encoding/hex"
	"fmt"
	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/decryptor/base/mocks"
	"github.com/cossacklabs/acra/logging"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"strings"
	"testing"

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

func (e *testEncryptor) EncryptWithZoneID(zoneIDdata, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	if acrastruct.ValidateAcraStructLength(data) == nil {
		return data, nil
	}
	e.fetchedIDs = append(e.fetchedIDs, zoneIDdata)
	return e.value, nil
}
func (e *testEncryptor) reset() {
	e.fetchedIDs = [][]byte{}
}

func (e *testEncryptor) EncryptWithClientID(clientID, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	if acrastruct.ValidateAcraStructLength(data) == nil {
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
	acrastruct, err := acrastruct.CreateAcrastruct([]byte("some data"), keypair.Public, nil)
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
			Query:             `INSERT INTO "TableWithoutColumnSchema" ("zone_id", "specified_client_id", "other_column", "default_client_id") VALUES ('%s', '%s', 1, '%s')`,
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
	parser := sqlparser.New(sqlparser.ModeStrict)
	mysqlParser, err := NewMysqlQueryEncryptor(schemaStore, parser, encryptor)
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
		ctx := base.SetAccessContextToContext(context.Background(), base.NewAccessContext(base.WithClientID(defaultClientID)))
		clientSession := &mocks.ClientSession{}
		sessionData := make(map[string]interface{}, 2)
		clientSession.On("GetData", mock.Anything).Return(sessionData, true)
		clientSession.On("SetData", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
			sessionData[args[0].(string)] = args[1]
		})
		ctx = base.SetClientSessionToContext(ctx, clientSession)
		data, changed, err := mysqlParser.OnQuery(ctx, base.NewOnQueryObjectFromQuery(query, parser))
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

func TestOnReturning(t *testing.T) {
	zoneIDStr := string(zone.GenerateZoneID())
	clientIDStr := "specified_client_id"
	defaultClientID := []byte("default_client_id")
	columns := []string{"other_column", "default_client_id", "specified_client_id", "zone_id"}

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
`, clientIDStr, zoneIDStr)
	schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(configStr))
	if err != nil {
		t.Fatalf("Can't parse config: %s", err.Error())
	}

	parser := sqlparser.New(sqlparser.ModeStrict)
	mysqlParser, err := NewMysqlQueryEncryptor(schemaStore, parser, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx := base.SetAccessContextToContext(context.Background(), base.NewAccessContext(base.WithClientID(defaultClientID)))
	clientSession := &mocks.ClientSession{}
	data := make(map[string]interface{}, 2)
	clientSession.On("GetData", mock.Anything).Return(data, true)
	clientSession.On("SetData", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		data[args[0].(string)] = args[1]
	})
	ctx = base.SetClientSessionToContext(ctx, clientSession)
	t.Run("RETURNING *", func(t *testing.T) {
		query := `INSERT INTO TableWithColumnSchema ('zone_id', 'specified_client_id', 'other_column', 'default_client_id') VALUES (1, 1, 1, 1) RETURNING *`

		_, _, err := mysqlParser.OnQuery(ctx, base.NewOnQueryObjectFromQuery(query, parser))
		if err != nil {
			t.Fatalf("%s", err.Error())
		}

		if len(columns) != len(mysqlParser.querySelectSettings) {
			t.Fatalf("Incorrect mysqlParser.querySelectSettings length")
		}

		expectedNilColumns := map[int]struct{}{
			0: {},
		}

		for i := range columns {
			if _, ok := expectedNilColumns[i]; ok {
				continue
			}
			setting := mysqlParser.querySelectSettings[i]

			if columns[i] != setting.columnName {
				t.Fatalf("%v. Incorrect QueryDataItem \nTook: %v\nExpected: %v", i, setting.columnName, columns[i])
			}
		}
	})

	t.Run("RETURNING columns", func(t *testing.T) {
		returning := "zone_id, specified_client_id, other_column, default_client_id"
		query := fmt.Sprintf(`INSERT INTO TableWithColumnSchema 
('zone_id', 'specified_client_id', 'other_column', 'default_client_id') VALUES (1, 1, 1, 1) RETURNING %s`, returning)

		_, _, err := mysqlParser.OnQuery(ctx, base.NewOnQueryObjectFromQuery(query, parser))
		if err != nil {
			t.Fatalf("%s", err.Error())
		}

		returningColumns := strings.Split(returning, ", ")
		if len(columns) != len(returningColumns) {
			t.Fatalf("Incorrect mysqlParser.querySelectSettings length")
		}

		expectedNilColumns := map[int]struct{}{
			2: {},
		}

		for i := range returningColumns {
			if _, ok := expectedNilColumns[i]; ok {
				continue
			}

			setting := mysqlParser.querySelectSettings[i]

			if returningColumns[i] != setting.columnName {
				t.Fatalf("%v. Incorrect QueryDataItem \nTook: %v\nExpected: %v", i, setting.columnName, columns[i])
			}
		}
	})
}

func TestEncryptionSettingCollection(t *testing.T) {
	type testcase struct {
		config   string
		settings []*QueryDataItem
		query    string
	}
	testcases := []testcase{
		// directly specified columns
		{config: `schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
    encrypted:
      - column: data1
      - column: data2
        crypto_envelope: acrablock`,
			query: `select data1, data2, data3 from test_table`,
			settings: []*QueryDataItem{
				{setting: &config.BasicColumnEncryptionSetting{Name: "data1"}, tableName: "test_table", columnName: "data1", columnAlias: "test_table"},
				{setting: &config.BasicColumnEncryptionSetting{Name: "data2"}, tableName: "test_table", columnName: "data2", columnAlias: "test_table"},
				nil,
			},
		},
		// no columns
		{config: `schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
    encrypted:
      - column: data1
      - column: data2
        crypto_envelope: acrablock`,
			query: `select 1 from test_table`,
			settings: []*QueryDataItem{
				nil,
			},
		},
		// simple query with Star
		{config: `schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
    encrypted:
      - column: data1
      - column: data2
        crypto_envelope: acrablock`,
			query: `select * from test_table`,
			settings: []*QueryDataItem{
				{setting: &config.BasicColumnEncryptionSetting{Name: "data1"}, tableName: "test_table", columnName: "data1", columnAlias: ""},
				{setting: &config.BasicColumnEncryptionSetting{Name: "data2"}, tableName: "test_table", columnName: "data2", columnAlias: ""},
				nil,
			},
		},
		// simple query with Star and literal
		{config: `schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
    encrypted:
      - column: data1
      - column: data2
        crypto_envelope: acrablock`,
			query: `select 'some string', * from test_table`,
			settings: []*QueryDataItem{
				nil,
				{setting: &config.BasicColumnEncryptionSetting{Name: "data1"}, tableName: "test_table", columnName: "data1", columnAlias: ""},
				{setting: &config.BasicColumnEncryptionSetting{Name: "data2"}, tableName: "test_table", columnName: "data2", columnAlias: ""},
				nil,
			},
		},
		// query contains table with alias
		{config: `schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
    encrypted:
      - column: data1
      - column: data2
        crypto_envelope: acrablock`,
			query: `select * from test_table t1`,
			settings: []*QueryDataItem{
				{setting: &config.BasicColumnEncryptionSetting{Name: "data1"}, tableName: "test_table", columnName: "data1", columnAlias: ""},
				{setting: &config.BasicColumnEncryptionSetting{Name: "data2"}, tableName: "test_table", columnName: "data2", columnAlias: ""},
				nil,
			},
		},
		// query has StarExpr with specified table
		{config: `schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
    encrypted:
      - column: data1
      - column: data2
        crypto_envelope: acrablock`,
			query: `select t1.* from test_table t1`,
			settings: []*QueryDataItem{
				{setting: &config.BasicColumnEncryptionSetting{Name: "data1"}, tableName: "test_table", columnName: "data1", columnAlias: ""},
				{setting: &config.BasicColumnEncryptionSetting{Name: "data2"}, tableName: "test_table", columnName: "data2", columnAlias: ""},
				nil,
			},
		},
		// query has StarExpr with several tables
		{config: `schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
    encrypted:
      - column: data1
      - column: data2
        crypto_envelope: acrablock
  - table: test_table2
    columns:
      - data1
      - data2
      - data3
    encrypted:
      - column: data1
      - column: data2
        crypto_envelope: acrablock`,
			query: `select t1.*, t2.* from test_table t1, test_table2 t2`,
			settings: []*QueryDataItem{
				{setting: &config.BasicColumnEncryptionSetting{Name: "data1"}, tableName: "test_table", columnName: "data1", columnAlias: ""},
				{setting: &config.BasicColumnEncryptionSetting{Name: "data2"}, tableName: "test_table", columnName: "data2", columnAlias: ""},
				nil,
				{setting: &config.BasicColumnEncryptionSetting{Name: "data1"}, tableName: "test_table2", columnName: "data1", columnAlias: ""},
				{setting: &config.BasicColumnEncryptionSetting{Name: "data2"}, tableName: "test_table2", columnName: "data2", columnAlias: ""},
				nil,
			},
		},
	}
	parser := sqlparser.New(sqlparser.ModeDefault)
	encryptor, err := NewPostgresqlQueryEncryptor(nil, parser, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, tcase := range testcases {
		t.Logf("Test tcase %d\n", i)
		schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(tcase.config))
		if err != nil {
			t.Fatal(err)
		}
		encryptor.schemaStore = schemaStore
		statement, err := parser.Parse(tcase.query)
		if err != nil {
			t.Fatal(err)
		}
		selectExpr, ok := statement.(*sqlparser.Select)
		if !ok {
			t.Fatalf("[%d] Test query should be SELECT query, took %s\n", i, tcase.query)
		}

		clientSession := &mocks.ClientSession{}
		data := make(map[string]interface{}, 2)
		clientSession.On("GetData", mock.Anything).Return(data, true)
		clientSession.On("SetData", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
			data[args[0].(string)] = args[1]
		})
		ctx := base.SetClientSessionToContext(context.Background(), clientSession)
		_, err = encryptor.onSelect(ctx, selectExpr)
		if err != nil {
			t.Fatal(err)
		}
		if len(encryptor.querySelectSettings) != len(tcase.settings) {
			t.Fatalf("Invalid count of settings. Expect %d, took %d\n", len(tcase.settings), len(encryptor.querySelectSettings))
		}
		for j := 0; j < len(tcase.settings); j++ {
			// check case if one of them is nil and another is not
			if (tcase.settings[j] == nil && encryptor.querySelectSettings[j] != nil) || (tcase.settings[j] != nil && encryptor.querySelectSettings[j] == nil) {
				t.Fatalf("[%d] Query select setting not equal to expected. Expect %v, took %v\n", i, tcase.settings[j], encryptor.querySelectSettings[j])
			}
			// we already compared and don't need to compare fields because nil
			if tcase.settings[j] == nil {
				continue
			}
			selectSettingEqual := encryptor.querySelectSettings[j].columnAlias != tcase.settings[j].columnAlias ||
				encryptor.querySelectSettings[j].tableName != tcase.settings[j].tableName ||
				encryptor.querySelectSettings[j].columnName != tcase.settings[j].columnName
			if selectSettingEqual {
				t.Fatalf("[%d] Query select setting not equal to expected. Expect %v, took %v\n", i, tcase.settings[j], encryptor.querySelectSettings[j])
			}
			if encryptor.querySelectSettings[j].setting.ColumnName() != tcase.settings[j].setting.ColumnName() {
				t.Fatalf("[%d] Encryption setting column names not equal to expected. Expect %v, took %v\n", i, tcase.settings[j].setting.ColumnName(), encryptor.querySelectSettings[j].setting.ColumnName())
			}
		}
	}
}

func TestEncryptionSettingCollectionFailures(t *testing.T) {
	type testcase struct {
		config string
		err    error
		query  string
	}
	testcases := []testcase{
		// unsupported aliased tables from expressions
		{config: `schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
    encrypted:
      - column: data1
      - column: data2
        crypto_envelope: acrablock`,
			query: `select * from (select * from test_table) as f`,
			err:   errNotFoundtable,
		},
	}
	parser := sqlparser.New(sqlparser.ModeDefault)
	encryptor, err := NewPostgresqlQueryEncryptor(nil, parser, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, tcase := range testcases {
		t.Logf("Test tcase %d\n", i)
		schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(tcase.config))
		if err != nil {
			t.Fatal(err)
		}
		encryptor.schemaStore = schemaStore
		statement, err := parser.Parse(tcase.query)
		if err != nil {
			t.Fatal(err)
		}
		selectExpr, ok := statement.(*sqlparser.Select)
		if !ok {
			t.Fatalf("[%d] Test query should be SELECT query, took %s\n", i, tcase.query)
		}
		_, err = encryptor.onSelect(context.TODO(), selectExpr)
		if err != tcase.err {
			t.Fatalf("Expect error %s, took %s\n", tcase.err, err)
		}
	}
}

func TestInsertWithIncorrectPlaceholdersAmount(t *testing.T) {
	type testcase struct {
		config      string
		err         error
		query       string
		expectedLog string
	}
	testcases := []testcase{
		// placeholders more than columns
		{config: `schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1`,
			query:       `insert into test_table(data1) values ($1, $2);`,
			err:         nil,
			expectedLog: "Amount of values in INSERT bigger than column count",
		},
		// placeholders more than columns with several data rows
		{config: `schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1`,
			query:       `insert into test_table(data1) values ($1), ($2, $3);`,
			err:         nil,
			expectedLog: "Amount of values in INSERT bigger than column count",
		},
	}
	parser := sqlparser.New(sqlparser.ModeDefault)

	encryptor, err := NewPostgresqlQueryEncryptor(nil, parser, NewChainDataEncryptor())
	if err != nil {
		t.Fatal(err)
	}
	// use custom output writer to check buffer for expected log entries
	logger := logrus.New()
	outBuffer := &bytes.Buffer{}
	logger.SetOutput(outBuffer)
	ctx := logging.SetLoggerToContext(context.Background(), logrus.NewEntry(logger))
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
	ctx = base.SetClientSessionToContext(ctx, clientSession)
	for i, tcase := range testcases {
		outBuffer.Reset()
		t.Logf("Test tcase %d\n", i)
		schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(tcase.config))
		if err != nil {
			t.Fatal(err)
		}
		encryptor.schemaStore = schemaStore
		statement, err := parser.Parse(tcase.query)
		if err != nil {
			t.Fatal(err)
		}
		insertExpr, ok := statement.(*sqlparser.Insert)
		if !ok {
			t.Fatalf("[%d] Test query should be INSERT query, took %s\n", i, tcase.query)
		}
		DeletePlaceholderSettingsFromClientSession(clientSession)
		bindData := PlaceholderSettingsFromClientSession(clientSession)
		_, err = encryptor.encryptInsertQuery(ctx, insertExpr, bindData)
		if err != tcase.err {
			t.Fatalf("Expect error %s, took %s\n", tcase.err, err)
		}
		strings.Contains(outBuffer.String(), tcase.expectedLog)
	}
}
