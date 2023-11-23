// /*
// Copyright 2018, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// */
package postgresql

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	pg_query "github.com/Zhaars/pg_query_go/v4"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"

	"github.com/cossacklabs/acra/acrastruct"
	decryptor "github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/mocks"
	"github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/sqlparser/dialect"
	"github.com/cossacklabs/acra/sqlparser/dialect/mysql"
	"github.com/cossacklabs/acra/sqlparser/dialect/postgresql"
)

type testEncryptor struct {
	value      []byte
	fetchedIDs [][]byte
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

type parserTestData struct {
	Query             string
	QueryData         []interface{}
	Normalized        bool
	ExpectedQueryData []interface{}
	Changed           bool
	ExpectedIDS       [][]byte
}

func testParsing(t *testing.T, testData []parserTestData, encryptedValue, defaultClientID []byte, schemaStore *config.MapTableSchemaStore) {
	encryptor := &testEncryptor{value: encryptedValue}
	parser := sqlparser.New(sqlparser.ModeStrict)
	queryEncryptor, err := NewQueryEncryptor(schemaStore, parser, encryptor)
	if err != nil {
		t.Fatal(err)
	}
	queryEncryptor.dataCoder = &PostgresqlPgQueryDBDataCoder{}
	var dialect dialect.Dialect = postgresql.NewPostgreSQLDialect()

	for i, testCase := range testData {
		encryptor.reset()

		query := fmt.Sprintf(testCase.Query, testCase.QueryData...)
		expectedQuery := fmt.Sprintf(testCase.Query, testCase.ExpectedQueryData...)
		if testCase.Normalized {
			expectedQuery, err = normalizeQueryWithDialect(dialect, expectedQuery)
			if err != nil {
				t.Fatalf("%v. Can't normalize query: %s - %s", i, err.Error(), query)
			}
		}
		ctx := decryptor.SetAccessContextToContext(context.Background(), decryptor.NewAccessContext(decryptor.WithClientID(defaultClientID)))
		clientSession := &mocks.ClientSession{}
		sessionData := make(map[string]interface{}, 2)
		clientSession.On("GetData", mock.Anything).Return(sessionData, true)
		clientSession.On("SetData", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
			sessionData[args[0].(string)] = args[1]
		})
		ctx = decryptor.SetClientSessionToContext(ctx, clientSession)
		data, changed, err := queryEncryptor.OnQuery(ctx, decryptor.NewOnQueryObjectFromQuery(query, parser))
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

//	func TestGeneralQueryParser_Parse(t *testing.T) {
//		clientIDStr := "specified_client_id"
//		specifiedClientID := []byte(clientIDStr)
//		defaultClientIDStr := "default_client_id"
//		defaultClientID := []byte(defaultClientIDStr)
//
//		keypair, err := keys.New(keys.TypeEC)
//		if err != nil {
//			t.Fatal(err)
//		}
//		acrastruct, err := acrastruct.CreateAcrastruct([]byte("some data"), keypair.Public, nil)
//		if err != nil {
//			t.Fatal(err)
//		}
//		hexAcrastruct := hex.EncodeToString(acrastruct)
//
//		configStr := fmt.Sprintf(`
//
// schemas:
//
//   - table: tablewithcolumnschema
//     columns: ["other_column", "default_client_id", "specified_client_id"]
//     encrypted:
//
//   - column: "default_client_id"
//
//   - column: specified_client_id
//     client_id: %s
//
//   - table: tablewithoutcolumnschema
//     encrypted:
//
//   - column: "default_client_id"
//
//   - column: specified_client_id
//     client_id: %s
//
// `, clientIDStr, clientIDStr)
//
//		schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(configStr), config.UseMySQL)
//		if err != nil {
//			t.Fatalf("Can't parse config: %s", err.Error())
//		}
//		simpleStringData := []byte("string data")
//		encryptedValue := []byte("encrypted")
//		hexEncryptedValue := hex.EncodeToString(encryptedValue)
//		dataValue := make([]byte, 256)
//		for i := 0; i < 256; i++ {
//			dataValue[i] = byte(i)
//		}
//		dataHexValue := hex.EncodeToString([]byte(dataValue))
//		// TODO add test cases with string, binary, int values. First should be decrypted as is, second as hex, third as is
//		testData := []parserTestData{
//			// 0. without list of columns and with schema, one value
//			{
//				Query:             `INSERT INTO TableWithColumnSchema VALUES (1, X'%s', X'%s')`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{defaultClientID, specifiedClientID},
//			},
//			// 1. without list of columns and with schema
//			{
//				Query:             `INSERT INTO TableWithColumnSchema VALUES (1, X'%s', X'%s'), (1, X'%s', X'%s')`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{hexEncryptedValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{defaultClientID, specifiedClientID, defaultClientID, specifiedClientID},
//			},
//			// 2. without list of columns and without schema
//			{
//				Query:             `INSERT INTO TableWithoutColumnSchema VALUES (1, X'%s', X'%s'), (1, X'%s', X'%s')`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
//				Normalized:        false,
//				Changed:           false,
//				ExpectedIDS:       [][]byte{},
//			},
//			// 3. with list of columns and without schema
//			{
//				Query:             `INSERT INTO TableWithoutColumnSchema (specified_client_id, other_column, default_client_id) VALUES (X'%s', 1, X'%s')`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//			},
//			// 4. insert with ON DUPLICATE without columns and with schema
//			{
//				Query:             `INSERT INTO TableWithColumnSchema VALUES (X'%s', X'%s', X'%s'), (1, X'%s', X'%s') ON DUPLICATE KEY UPDATE other_column=X'%s', specified_client_id=X'%s', default_client_id=X'%s';`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue, hexEncryptedValue, dataHexValue, hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{defaultClientID, specifiedClientID, defaultClientID, specifiedClientID, specifiedClientID, defaultClientID},
//			},
//			// 5. insert with ON DUPLICATE without columns and without schema
//			{
//				Query:             `INSERT INTO TableWithoutColumnSchema VALUES (X'%s', X'%s', X'%s') ON DUPLICATE KEY UPDATE other_column=X'%s', specified_client_id=X'%s', default_client_id=X'%s';`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//			},
//			// 6. insert with ON DUPLICATE with columns and without schema
//			{
//				Query:             `INSERT INTO TableWithoutColumnSchema (specified_client_id, other_column, default_client_id) VALUES (X'%s', X'%s', X'%s') ON DUPLICATE KEY UPDATE default_client_id=X'%s', other_column=X'%s', specified_client_id=X'%s';`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{hexEncryptedValue, dataHexValue, hexEncryptedValue, hexEncryptedValue, dataHexValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID, defaultClientID, specifiedClientID},
//			},
//			// 7. insert without encryption
//			{
//				Query:             `INSERT INTO TableWithoutColumnSchema (other_column, other_column) VALUES (X'%s', X'%s') ON DUPLICATE KEY UPDATE other_column=X'%s', other_column=X'%s';`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
//				Normalized:        false,
//				Changed:           false,
//				ExpectedIDS:       [][]byte{},
//			},
//			// 8. insert without table info
//			{
//				Query:             `INSERT INTO UnknownTable (other_column, specified_client_id, default_client_id) VALUES (X'%s', X'%s', X'%s') ON DUPLICATE KEY UPDATE other_column=X'%s', other_column=X'%s';`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue, dataHexValue},
//				Normalized:        false,
//				Changed:           false,
//				ExpectedIDS:       [][]byte{},
//			},
//			// 9. update with encryptable and not encryptable column
//			{
//				Query:             `UPDATE TableWithoutColumnSchema as t set other_column=X'%s', specified_client_id=X'%s', default_client_id=X'%s'`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//			},
//			// 10. update without encryption
//			{
//				Query:             `UPDATE TableWithoutColumnSchema set other_column=X'%s', other_column=X'%s'`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, dataHexValue},
//				Normalized:        false,
//				Changed:           false,
//				ExpectedIDS:       [][]byte{},
//			},
//			// 11. update without table info
//			{
//				Query:             `UPDATE UnknownTable set other_column=X'%s', other_column=X'%s', specified_client_id=X'%s', default_client_id=X'%s'`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, dataHexValue, dataHexValue, dataHexValue},
//				Normalized:        false,
//				Changed:           false,
//				ExpectedIDS:       [][]byte{},
//			},
//			// 12. aliased update with encryptable and not encryptable column
//			{
//				Query:             `UPDATE TableWithoutColumnSchema as t set other_column=X'%s', t.specified_client_id=X'%s', default_client_id=X'%s'`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//			},
//			// 13. update with two tables with encryptable and not encryptable column
//			{
//				Query:             `UPDATE TableWithoutColumnSchema, TableWithoutColumnSchema as t2, UnknownTable as un set un.other_column=X'%s', t2.specified_client_id=X'%s', default_client_id=X'%s'`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//			},
//			// 14. insert with subquery and ON DUPLICATE
//			{
//				Query:             `INSERT INTO TableWithoutColumnSchema (other_column, specified_client_id, default_client_id) SELECT * FROM TableWithoutColumnSchema ON DUPLICATE KEY UPDATE other_column=X'%s', specified_client_id=X'%s', default_client_id=X'%s'`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//			},
//			// 15. insert with subquery
//			{
//				Query:             `INSERT INTO TableWithoutColumnSchema (other_column, specified_client_id, default_client_id) SELECT * FROM TableWithoutColumnSchema`,
//				QueryData:         []interface{}{},
//				ExpectedQueryData: []interface{}{},
//				Normalized:        false,
//				Changed:           false,
//				ExpectedIDS:       [][]byte{},
//			},
//			// 16. insert with SET expressions
//			{
//				Query:             `INSERT INTO TableWithoutColumnSchema SET other_column=X'%s', specified_client_id=X'%s', default_client_id=X'%s'`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//			},
//			// 17. update with join
//			{
//				Query:             `UPDATE TableWithoutColumnSchema INNER JOIN TableWithoutColumnSchema as t2 on t2.id=TableWithoutColumnSchema.id, (SELECT * FROM UnknownTable) as un set un.other_column=X'%s', t2.specified_client_id=X'%s', default_client_id=X'%s'`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//			},
//			// 18. update with parenthesized tables
//			{
//				Query:             `UPDATE (TableWithoutColumnSchema, TableWithoutColumnSchema as t2, UnknownTable as un) SET un.other_column=X'%s', t2.specified_client_id=X'%s', default_client_id=X'%s'`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//			},
//			// 19. INSERT with ignorable acrastruct
//			{
//				Query:             `INSERT INTO TableWithColumnSchema VALUES (1, X'%s', X'%s')`,
//				QueryData:         []interface{}{hexAcrastruct, hexAcrastruct},
//				ExpectedQueryData: []interface{}{hexAcrastruct, hexAcrastruct},
//				Normalized:        false,
//				Changed:           false,
//				ExpectedIDS:       [][]byte{},
//			},
//			// 20. update ignorable acrastruct
//			{
//				Query:             `UPDATE TableWithoutColumnSchema as t set other_column=X'%s', specified_client_id=X'%s', default_client_id=X'%s'`,
//				QueryData:         []interface{}{dataHexValue, hexAcrastruct, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, hexAcrastruct, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{defaultClientID},
//			},
//			// 21. with double quoted table and column names
//			{
//				Query:             `INSERT INTO "TableWithoutColumnSchema" ("specified_client_id", "other_column", "default_client_id") VALUES (X'%s', 1, X'%s')`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//				dialect:           mysql.NewMySQLDialect(mysql.SetANSIMode(true)),
//			},
//			// 22. with back quoted table and column names
//			{
//				Query:             "INSERT INTO `TableWithoutColumnSchema` (`specified_client_id`, `other_column`, `default_client_id`) VALUES (X'%s', 1, X'%s')",
//				QueryData:         []interface{}{dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//			},
//			// 23. update with double quoted identifiers
//			{
//				Query:             `UPDATE "TableWithoutColumnSchema" as "t" set "other_column"=X'%s', "specified_client_id"=X'%s', "default_client_id"=X'%s'`,
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//				dialect:           mysql.NewMySQLDialect(mysql.SetANSIMode(true)),
//			},
//			// 24. update with back quoted identifiers
//			{
//				Query:             "UPDATE `TableWithoutColumnSchema` as `t` set `other_column`=X'%s', `specified_client_id`=X'%s', `default_client_id`=X'%s'",
//				QueryData:         []interface{}{dataHexValue, dataHexValue, dataHexValue},
//				ExpectedQueryData: []interface{}{dataHexValue, hexEncryptedValue, hexEncryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//			},
//			// 25. insert with data as simple string
//			{
//				Query:             `INSERT INTO "TableWithoutColumnSchema" ("specified_client_id", "other_column", "default_client_id") VALUES ('%s', 1, '%s')`,
//				QueryData:         []interface{}{simpleStringData, simpleStringData},
//				ExpectedQueryData: []interface{}{encryptedValue, encryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//				dialect:           mysql.NewMySQLDialect(mysql.SetANSIMode(true)),
//			},
//			// 26. update with data as simple string
//			{
//				Query:             `UPDATE "TableWithoutColumnSchema" as "t" set "other_column"='%s', "specified_client_id"='%s', "default_client_id"='%s'`,
//				QueryData:         []interface{}{simpleStringData, simpleStringData, simpleStringData},
//				ExpectedQueryData: []interface{}{simpleStringData, encryptedValue, encryptedValue},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//				dialect:           mysql.NewMySQLDialect(mysql.SetANSIMode(true)),
//			},
//
//			// 27. insert with data as simple string for postgresql
//			{
//				Query:             `INSERT INTO "tablewithoutcolumnschema" ("specified_client_id", "other_column", "default_client_id") VALUES ('%s', 1, '%s')`,
//				QueryData:         []interface{}{simpleStringData, simpleStringData},
//				ExpectedQueryData: []interface{}{PgEncodeToHexString(encryptedValue), PgEncodeToHexString(encryptedValue)},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//				DataCoder:         &PostgresqlDBDataCoder{},
//				dialect:           postgresql.NewPostgreSQLDialect(),
//			},
//			// 28. update with data as simple string for postgresql
//			{
//				Query:             `UPDATE "tablewithoutcolumnschema" as "t" set "other_column"='%s', "specified_client_id"='%s', "default_client_id"='%s'`,
//				QueryData:         []interface{}{simpleStringData, simpleStringData, simpleStringData},
//				ExpectedQueryData: []interface{}{simpleStringData, PgEncodeToHexString(encryptedValue), PgEncodeToHexString(encryptedValue)},
//				Normalized:        true,
//				Changed:           true,
//				ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
//				DataCoder:         &PostgresqlDBDataCoder{},
//				dialect:           postgresql.NewPostgreSQLDialect(),
//			},
//		}
//
//		testParsing(t, testData, encryptedValue, defaultClientID, schemaStore)
//	}
func TestCaseSensitivity_PostgreSQLWithQuotes(t *testing.T) {
	clientIDStr := "specified_client_id"
	specifiedClientID := []byte(clientIDStr)
	defaultClientIDStr := "default_client_id"
	defaultClientID := []byte(defaultClientIDStr)

	configStr := fmt.Sprintf(`
schemas:
  - table: lowercasetable
    columns: ["other_column", "default_client_id", "specified_client_id"]
    encrypted:
      - column: "DEFAULT_client_id"
      - column: specified_client_id
        client_id: %s

  - table: UPPERCASETABLE
    columns: ["other_column", "DEFAULT_client_id", "specified_client_id"]
    encrypted:
      - column: "DEFAULT_client_id"
      - column: specified_client_id
        client_id: %s
`, clientIDStr, clientIDStr)

	schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(configStr), config.UseMySQL)
	if err != nil {
		t.Fatalf("Can't parse config: %s", err.Error())
	}
	simpleStringData := []byte("string data")
	encryptedValue := []byte("encrypted")
	dataValue := make([]byte, 256)
	for i := 0; i < 256; i++ {
		dataValue[i] = byte(i)
	}
	testData := []parserTestData{
		// Testing behavior of PostgreSQL parser: before comparing with things in encryptor config
		// - raw identifiers (table, column names) should be converted to lowercase
		// - if wrapped with double quotes, should be taken as is
		// see https://www.postgresql.org/docs/current/sql-syntax-lexical.html

		// 0. should match, lowercase config identifier == lowercase SQL identifier
		// update lowercasetable set other_column = 'string data', specified_client_id = E'\\x656e63727970746564', "DEFAULT_client_id" = E'\\x656e63727970746564'
		{
			Query:             `UPDATE lowercasetable set other_column='%s', specified_client_id=E'%s', "DEFAULT_client_id"=E'%s'`,
			QueryData:         []interface{}{simpleStringData, simpleStringData, simpleStringData},
			ExpectedQueryData: []interface{}{simpleStringData, PgEncodeToHexString(encryptedValue), PgEncodeToHexString(encryptedValue)},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
		},
		// 1. should partially match, like #0 but DEFAULT_client_id is not quoted and is processed as lowercase
		{
			Query:             `UPDATE lowercasetable set other_column='%s', specified_client_id=E'%s', default_client_id='%s'`,
			QueryData:         []interface{}{simpleStringData, simpleStringData, simpleStringData},
			ExpectedQueryData: []interface{}{simpleStringData, PgEncodeToHexString(encryptedValue), simpleStringData},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{specifiedClientID},
		},
		// 2. should match, lowercase config identifier == lowercase SQL identifier
		{
			Query:             `UPDATE lowercasetable set other_column='%s', specified_client_id=E'%s', "DEFAULT_client_id"=E'%s'`,
			QueryData:         []interface{}{simpleStringData, simpleStringData, simpleStringData},
			ExpectedQueryData: []interface{}{simpleStringData, PgEncodeToHexString(encryptedValue), PgEncodeToHexString(encryptedValue)},
			Normalized:        true,
			Changed:           true,
			ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
		},
		//// 3. should match, lowercase config identifier == lowercase SQL identifier (converted)
		//{
		//	Query:             `UPDATE LOWERCASETABLE set other_column='%s', specified_client_id=E'%s', "DEFAULT_client_id"=E'%s'`,
		//	QueryData:         []interface{}{simpleStringData, simpleStringData, simpleStringData},
		//	ExpectedQueryData: []interface{}{simpleStringData, PgEncodeToHexString(encryptedValue), PgEncodeToHexString(encryptedValue)},
		//	Normalized:        true,
		//	Changed:           true,
		//	ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
		//},
		//// 4. should NOT match, lowercase config identifier != uppercase SQL identifier
		//{
		//	Query:             `UPDATE "LOWERCASETABLE" set other_column='%s', specified_client_id='%s', "DEFAULT_client_id"='%s'`,
		//	QueryData:         []interface{}{simpleStringData, simpleStringData, simpleStringData},
		//	ExpectedQueryData: []interface{}{simpleStringData, simpleStringData, simpleStringData},
		//	Normalized:        false,
		//	Changed:           false,
		//	ExpectedIDS:       [][]byte{},
		//	DataCoder:         &PostgresqlDBDataCoder{},
		//	dialect:           postgresql.NewPostgreSQLDialect(),
		//},
		//// 5. should NOT match, uppercase config identifier != lowercase SQL identifier
		//{
		//	Query:             `UPDATE uppercasetable set other_column='%s', specified_client_id='%s', "DEFAULT_client_id"='%s'`,
		//	QueryData:         []interface{}{simpleStringData, simpleStringData, simpleStringData},
		//	ExpectedQueryData: []interface{}{simpleStringData, simpleStringData, simpleStringData},
		//	Normalized:        false,
		//	Changed:           false,
		//	ExpectedIDS:       [][]byte{},
		//	DataCoder:         &PostgresqlDBDataCoder{},
		//	dialect:           postgresql.NewPostgreSQLDialect(),
		//},
		//// 6. should NOT match, uppercase config identifier != lowercase SQL identifier
		//{
		//	Query:             `UPDATE "uppercasetable" set other_column='%s', specified_client_id='%s', "DEFAULT_client_id"='%s'`,
		//	QueryData:         []interface{}{simpleStringData, simpleStringData, simpleStringData},
		//	ExpectedQueryData: []interface{}{simpleStringData, simpleStringData, simpleStringData},
		//	Normalized:        false,
		//	Changed:           false,
		//	ExpectedIDS:       [][]byte{},
		//	DataCoder:         &PostgresqlDBDataCoder{},
		//	dialect:           postgresql.NewPostgreSQLDialect(),
		//},
		//// 7. should NOT match, uppercase config identifier != lowercase SQL identifier (converted)
		//{
		//	Query:             `UPDATE UPPERCASETABLE set other_column='%s', specified_client_id='%s', "DEFAULT_client_id"='%s'`,
		//	QueryData:         []interface{}{simpleStringData, simpleStringData, simpleStringData},
		//	ExpectedQueryData: []interface{}{simpleStringData, simpleStringData, simpleStringData},
		//	Normalized:        false,
		//	Changed:           false,
		//	ExpectedIDS:       [][]byte{},
		//	DataCoder:         &PostgresqlDBDataCoder{},
		//	dialect:           postgresql.NewPostgreSQLDialect(),
		//},
		//// 8. should match, uppercase config identifier == uppercase SQL identifier
		//{
		//	Query:             `UPDATE "UPPERCASETABLE" set "other_column"='%s', "specified_client_id"='%s', "DEFAULT_client_id"='%s'`,
		//	QueryData:         []interface{}{simpleStringData, simpleStringData, simpleStringData},
		//	ExpectedQueryData: []interface{}{simpleStringData, PgEncodeToHexString(encryptedValue), PgEncodeToHexString(encryptedValue)},
		//	Normalized:        true,
		//	Changed:           true,
		//	ExpectedIDS:       [][]byte{specifiedClientID, defaultClientID},
		//	DataCoder:         &PostgresqlDBDataCoder{},
		//	dialect:           postgresql.NewPostgreSQLDialect(),
		//},
	}

	testParsing(t, testData, encryptedValue, defaultClientID, schemaStore)
}

func TestOnReturning(t *testing.T) {
	clientIDStr := "specified_client_id"
	defaultClientID := []byte("default_client_id")
	columns := []string{"other_column", "default_client_id", "specified_client_id", "common_field"}

	configStr := fmt.Sprintf(`
schemas:
  - table: tablewithcolumnschema
    columns: ["other_column", "default_client_id", "specified_client_id", "common_field"]
    encrypted: 
      - column: "default_client_id"
      - column: specified_client_id
        client_id: %s
      - column: common_field

  - table: tablewithcolumnschema_2
    columns: ["other_column_2", "default_client_id_2", "specified_client_id_2", "common_field"]
    encrypted: 
      - column: "default_client_id_2"
      - column: specified_client_id_2
        client_id: %s
      - column: common_field
`, clientIDStr, clientIDStr)
	schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(configStr), config.UseMySQL)
	if err != nil {
		t.Fatalf("Can't parse config: %s", err.Error())
	}

	parser := sqlparser.New(sqlparser.ModeStrict)
	encryptor, err := NewQueryEncryptor(schemaStore, parser, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx := decryptor.SetAccessContextToContext(context.Background(), decryptor.NewAccessContext(decryptor.WithClientID(defaultClientID)))
	clientSession := &mocks.ClientSession{}
	data := make(map[string]interface{}, 2)
	clientSession.On("GetData", mock.Anything).Return(data, true)
	clientSession.On("SetData", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		data[args[0].(string)] = args[1]
	})
	ctx = decryptor.SetClientSessionToContext(ctx, clientSession)
	t.Run("RETURNING *", func(t *testing.T) {
		query := `INSERT INTO TableWithColumnSchema (specified_client_id, other_column, default_client_id) VALUES (1, 1, 1) RETURNING *`

		_, _, err := encryptor.OnQuery(ctx, decryptor.NewOnQueryObjectFromQuery(query, parser))
		if err != nil {
			t.Fatalf("%s", err.Error())
		}

		if len(columns) != len(encryptor.querySelectSettings) {
			t.Fatalf("Incorrect encryptor.querySelectSettings length")
		}

		expectedNilColumns := map[int]struct{}{
			0: {},
		}

		for i := range columns {
			if _, ok := expectedNilColumns[i]; ok {
				continue
			}
			setting := encryptor.querySelectSettings[i]

			if columns[i] != setting.ColumnName() {
				t.Fatalf("%v. Incorrect QueryDataItem \nTook: %v\nExpected: %v", i, setting.ColumnName(), columns[i])
			}
		}
	})

	t.Run("RETURNING columns", func(t *testing.T) {
		returning := "specified_client_id, other_column, default_client_id"
		query := fmt.Sprintf(`INSERT INTO TableWithColumnSchema (specified_client_id, other_column, default_client_id) VALUES (1, 1, 1) RETURNING %s`, returning)

		_, _, err := encryptor.OnQuery(ctx, decryptor.NewOnQueryObjectFromQuery(query, parser))
		if err != nil {
			t.Fatalf("%s", err.Error())
		}

		returningColumns := strings.Split(returning, ", ")
		if len(encryptor.querySelectSettings) != len(returningColumns) {
			t.Fatalf("Incorrect encryptor.querySelectSettings length")
		}

		expectedNilColumns := map[int]struct{}{
			1: {},
		}

		for i := range returningColumns {
			if _, ok := expectedNilColumns[i]; ok {
				continue
			}

			setting := encryptor.querySelectSettings[i]

			if returningColumns[i] != setting.ColumnName() {
				t.Fatalf("%v. Incorrect QueryDataItem \nTook: %v\nExpected: %v", i, setting.ColumnName(), columns[i])
			}
		}
	})

	t.Run("RETURNING columns with sql literals", func(t *testing.T) {
		sqlparser.SetDefaultDialect(postgresql.NewPostgreSQLDialect())

		returning := "1, 0 as literal, specified_client_id, other_column, default_client_id, NULL"
		queryTemplates := []string{
			"INSERT INTO TableWithColumnSchema (specified_client_id, other_column, default_client_id) VALUES (1, 1, 1) RETURNING %s",
			//"UPDATE TableWithColumnSchema SET price = price * 1.10 WHERE price <= 99.99 RETURNING %s",
			//"DELETE FROM TableWithColumnSchema WHERE price <= 99.99 RETURNING %s",
		}

		for _, template := range queryTemplates {
			query := fmt.Sprintf(template, returning)

			_, _, err := encryptor.OnQuery(ctx, decryptor.NewOnQueryObjectFromQuery(query, parser))
			if err != nil {
				t.Fatalf("%s", err.Error())
			}

			returningColumns := strings.Split(returning, ", ")
			if len(encryptor.querySelectSettings) != len(returningColumns) {
				t.Fatalf("Incorrect encryptor.querySelectSettings length")
			}

			expectedNilColumns := map[int]struct{}{
				0: {},
				1: {},
				3: {},
				5: {},
			}

			for i := range returningColumns {
				if _, ok := expectedNilColumns[i]; ok {
					continue
				}

				setting := encryptor.querySelectSettings[i]

				if returningColumns[i] != setting.ColumnName() {
					t.Fatalf("%v. Incorrect QueryDataItem \nTook: %v\nExpected: %v", i, setting.ColumnName(), columns[i])
				}
			}
		}
	})

	t.Run("RETURNING columns with sql literals and several tables from config", func(t *testing.T) {
		sqlparser.SetDefaultDialect(postgresql.NewPostgreSQLDialect())

		returning := "specified_client_id, specified_client_id_2, default_client_id, default_client_id_2"
		returningWithAliases := "t1.specified_client_id, t2.specified_client_id_2, t1.default_client_id, t2.default_client_id_2, t1.common_field, t2.common_field"
		testCases := []struct {
			template       string
			returning      string
			expectedTables []string
		}{
			{
				template:  "UPDATE TableWithColumnSchema SET specified_client_id = t2.specified_client_id FROM TableWithColumnSchema_2 as t2 RETURNING %s",
				returning: returning,
				expectedTables: []string{
					"tablewithcolumnschema",
					"tablewithcolumnschema_2",
					"tablewithcolumnschema",
					"tablewithcolumnschema_2",
				},
			},
			{
				template:  "UPDATE TableWithColumnSchema as t1 SET specified_client_id = t2.specified_client_id FROM TableWithColumnSchema_2 as t2 RETURNING %s",
				returning: returningWithAliases,
				expectedTables: []string{
					"tablewithcolumnschema",
					"tablewithcolumnschema_2",
					"tablewithcolumnschema",
					"tablewithcolumnschema_2",
					"tablewithcolumnschema",
					"tablewithcolumnschema_2",
				},
			},
			{
				template:  "DELETE FROM TableWithColumnSchema USING TableWithColumnSchema_2  WHERE specified_client_id_2 = specified_client_id RETURNING %s",
				returning: returning,
				expectedTables: []string{
					"tablewithcolumnschema",
					"tablewithcolumnschema_2",
					"tablewithcolumnschema",
					"tablewithcolumnschema_2",
				},
			},
			{
				template:  "DELETE FROM TableWithColumnSchema as t1 USING TableWithColumnSchema_2 as t2 WHERE specified_client_id_2 = specified_client_id RETURNING %s",
				returning: returningWithAliases,
				expectedTables: []string{
					"tablewithcolumnschema",
					"tablewithcolumnschema_2",
					"tablewithcolumnschema",
					"tablewithcolumnschema_2",
					"tablewithcolumnschema",
					"tablewithcolumnschema_2",
				},
			},
		}

		for _, tcase := range testCases {
			query := fmt.Sprintf(tcase.template, tcase.returning)

			_, _, err := encryptor.OnQuery(ctx, decryptor.NewOnQueryObjectFromQuery(query, parser))
			if err != nil {
				t.Fatalf("%s", err.Error())
			}

			returningColumns := strings.Split(tcase.returning, ", ")
			if len(encryptor.querySelectSettings) != len(returningColumns) {
				t.Fatalf("Incorrect encryptor.querySelectSettings length")
			}

			for i := range returningColumns {
				setting := encryptor.querySelectSettings[i]
				if setting == nil {
					t.Fatalf("expected setting not to be nil")
				}

				if setting.TableName() != tcase.expectedTables[i] {
					t.Fatalf("Unexpected setting.tableName, expected %s but got %s", tcase.expectedTables[i], setting.TableName())
				}
			}
		}
	})

	t.Run("RETURNING columns with sql literals and several tables", func(t *testing.T) {
		sqlparser.SetDefaultDialect(postgresql.NewPostgreSQLDialect())

		returning := "specified_client_id_2, specified_unknown_column, default_client_id_2, default_unknown_column"
		queryTemplates := []string{
			"UPDATE UnknownTable SET specified_client_id = t2.specified_client_id FROM TableWithColumnSchema_2 as t2 RETURNING %s",
			"UPDATE TableWithColumnSchema_2 as t2  SET specified_client_id = t2.specified_client_id FROM UnknownTable RETURNING %s",
			"DELETE FROM UnknownTable USING TableWithColumnSchema_2 as t2 WHERE t2.specified_client_id = default_unknown_column RETURNING %s",
			"DELETE FROM TableWithColumnSchema_2 USING UnknownTable WHERE specified_client_id = default_unknown_column RETURNING %s",
		}

		for _, template := range queryTemplates {
			query := fmt.Sprintf(template, returning)

			_, _, err := encryptor.OnQuery(ctx, decryptor.NewOnQueryObjectFromQuery(query, parser))
			if err != nil {
				t.Fatalf("%s", err.Error())
			}

			returningColumns := strings.Split(returning, ", ")
			if len(encryptor.querySelectSettings) != len(returningColumns) {
				t.Fatalf("Incorrect encryptor.querySelectSettings length")
			}

			tableFromConfig := "tablewithcolumnschema_2"
			expectedTables := map[int]*string{
				0: &tableFromConfig,
				1: nil,
				2: &tableFromConfig,
				3: nil,
			}

			for i := range returningColumns {
				setting := encryptor.querySelectSettings[i]

				if expectedTables[i] == nil && setting != nil {
					t.Fatalf("Expected setting to be nil, but got %s", setting)
				}

				if expectedTables[i] != nil && setting == nil {
					t.Fatalf("Expected setting not to be nil, but got nil")
				}

				if table := expectedTables[i]; table != nil {
					if *table != setting.TableName() {
						t.Fatalf("Unexpected setting table name, want %s but got %s", *table, setting.TableName())
					}
				}
			}
		}
	})

	t.Run("RETURNING with star and several tables", func(t *testing.T) {
		sqlparser.SetDefaultDialect(postgresql.NewPostgreSQLDialect())

		returning := "*"
		queryTemplates := []string{
			"UPDATE TableWithColumnSchema SET specified_client_id = t2.specified_client_id FROM TableWithColumnSchema_2 as t2 RETURNING %s",
			"DELETE FROM TableWithColumnSchema USING TableWithColumnSchema_2 as t2  WHERE did = t2.did RETURNING %s",
		}

		tableSchema := schemaStore.GetTableSchema("tablewithcolumnschema")
		table2Schema := schemaStore.GetTableSchema("tablewithcolumnschema_2")

		expectSettingNumber := len(tableSchema.Columns()) + len(table2Schema.Columns())

		for _, template := range queryTemplates {
			query := fmt.Sprintf(template, returning)

			_, _, err := encryptor.OnQuery(ctx, decryptor.NewOnQueryObjectFromQuery(query, parser))
			if err != nil {
				t.Fatalf("%s", err.Error())
			}

			expectedNilColumns := map[int]struct{}{
				0: {},
				4: {},
			}

			if expectSettingNumber != len(encryptor.querySelectSettings) {
				t.Fatalf("Incorrect number of  encryptor.querySelectSettings")
			}

			for i := 0; i < expectSettingNumber; i++ {
				if _, ok := expectedNilColumns[i]; ok {
					setting := encryptor.querySelectSettings[i]

					if setting != nil {
						t.Fatalf("Expected nil setting, but got not %s", setting.ColumnName())
					}
				}
			}
		}
	})
}
func TestEncryptionSettingCollection(t *testing.T) {
	type testcase struct {
		config   string
		settings []*base.QueryDataItem
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
			settings: []*base.QueryDataItem{
				base.NewQueryDataItem(&config.BasicColumnEncryptionSetting{Name: "data1"}, "test_table", "data1", "test_table"),
				base.NewQueryDataItem(&config.BasicColumnEncryptionSetting{Name: "data2"}, "test_table", "data2", "test_table"),
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
			settings: []*base.QueryDataItem{
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
			settings: []*base.QueryDataItem{
				base.NewQueryDataItem(&config.BasicColumnEncryptionSetting{Name: "data1"}, "test_table", "data1", ""),
				base.NewQueryDataItem(&config.BasicColumnEncryptionSetting{Name: "data2"}, "test_table", "data2", ""),
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
			settings: []*base.QueryDataItem{
				nil,
				base.NewQueryDataItem(&config.BasicColumnEncryptionSetting{Name: "data1"}, "test_table", "data1", ""),
				base.NewQueryDataItem(&config.BasicColumnEncryptionSetting{Name: "data2"}, "test_table", "data2", ""),
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
			settings: []*base.QueryDataItem{
				base.NewQueryDataItem(&config.BasicColumnEncryptionSetting{Name: "data1"}, "test_table", "data1", ""),
				base.NewQueryDataItem(&config.BasicColumnEncryptionSetting{Name: "data2"}, "test_table", "data2", ""),
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
			settings: []*base.QueryDataItem{
				base.NewQueryDataItem(&config.BasicColumnEncryptionSetting{Name: "data1"}, "test_table", "data1", ""),
				base.NewQueryDataItem(&config.BasicColumnEncryptionSetting{Name: "data2"}, "test_table", "data2", ""),
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
			settings: []*base.QueryDataItem{
				base.NewQueryDataItem(&config.BasicColumnEncryptionSetting{Name: "data1"}, "test_table", "data1", ""),
				base.NewQueryDataItem(&config.BasicColumnEncryptionSetting{Name: "data2"}, "test_table", "data2", ""),
				nil,
				base.NewQueryDataItem(&config.BasicColumnEncryptionSetting{Name: "data1"}, "test_table2", "data1", ""),
				base.NewQueryDataItem(&config.BasicColumnEncryptionSetting{Name: "data2"}, "test_table2", "data2", ""),
				nil,
			},
		},
	}
	parser := sqlparser.New(sqlparser.ModeDefault)
	encryptor, err := NewQueryEncryptor(nil, parser, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, tcase := range testcases {
		t.Logf("Test tcase %d\n", i)
		schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(tcase.config), config.UseMySQL)
		if err != nil {
			t.Fatal(err)
		}
		encryptor.schemaStore = schemaStore
		statement, err := pg_query.Parse(tcase.query)
		if err != nil {
			t.Fatal(err)
		}

		clientSession := &mocks.ClientSession{}
		data := make(map[string]interface{}, 2)
		clientSession.On("GetData", mock.Anything).Return(data, true)
		clientSession.On("SetData", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
			data[args[0].(string)] = args[1]
		})
		ctx := decryptor.SetClientSessionToContext(context.Background(), clientSession)
		_, err = encryptor.onSelect(ctx, statement.Stmts[0].Stmt.GetSelectStmt())
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
			selectSettingEqual := encryptor.querySelectSettings[j].ColumnAlias() != tcase.settings[j].ColumnAlias() ||
				encryptor.querySelectSettings[j].TableName() != tcase.settings[j].TableName() ||
				encryptor.querySelectSettings[j].ColumnName() != tcase.settings[j].ColumnName()
			if selectSettingEqual {
				t.Fatalf("[%d] Query select setting not equal to expected. Expect %v, took %v\n", i, tcase.settings[j], encryptor.querySelectSettings[j])
			}
			if encryptor.querySelectSettings[j].Setting().ColumnName() != tcase.settings[j].Setting().ColumnName() {
				t.Fatalf("[%d] Encryption setting column names not equal to expected. Expect %v, took %v\n", i, tcase.settings[j].Setting().ColumnName(), encryptor.querySelectSettings[j].Setting().ColumnName())
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
	encryptor, err := NewQueryEncryptor(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, tcase := range testcases {
		t.Logf("Test tcase %d\n", i)
		schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(tcase.config), config.UseMySQL)
		if err != nil {
			t.Fatal(err)
		}
		encryptor.schemaStore = schemaStore
		statement, err := pg_query.Parse(tcase.query)
		if err != nil {
			t.Fatal(err)
		}

		_, err = encryptor.onSelect(context.TODO(), statement.Stmts[0].Stmt.GetSelectStmt())
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

	encryptor, err := NewQueryEncryptor(nil, parser, base.NewChainDataEncryptor())
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
	ctx = decryptor.SetClientSessionToContext(ctx, clientSession)
	for i, tcase := range testcases {
		outBuffer.Reset()
		t.Logf("Test tcase %d\n", i)
		schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(tcase.config), config.UseMySQL)
		if err != nil {
			t.Fatal(err)
		}
		encryptor.schemaStore = schemaStore

		statement, err := pg_query.Parse(tcase.query)
		if err != nil {
			t.Fatal(err)
		}
		base.DeletePlaceholderSettingsFromClientSession(clientSession)
		bindData := base.PlaceholderSettingsFromClientSession(clientSession)
		_, err = encryptor.encryptInsertQuery(ctx, statement.Stmts[0].Stmt.GetInsertStmt(), bindData)
		if err != tcase.err {
			t.Fatalf("Expect error %s, took %s\n", tcase.err, err)
		}
		strings.Contains(outBuffer.String(), tcase.expectedLog)
	}
}
