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
	"encoding/hex"
	"fmt"
	"github.com/xwb1989/sqlparser"
	"gopkg.in/yaml.v2"
	"testing"
)

type testEncryptor struct{ value []byte }

func (e *testEncryptor) Encrypt(data []byte) ([]byte, error) {
	return e.value, nil
}

// normalizeQuery convert to lower case parts that case-insensitive
func normalizeQuery(query string, t *testing.T) string {
	parsed, err := sqlparser.Parse(query)
	if err != nil {
		t.Fatal(err)
	}
	return sqlparser.String(parsed)
}

func TestMysqlQueryParser_Parse(t *testing.T) {
	type T struct {
		Schemas []TableScheme
	}
	tt := &T{}
	err := yaml.Unmarshal([]byte(`
schemas:
  - table: test
    columns:
      - id
      - data
      - raw_data
    encrypted:
      - data

  - table: test2
    columns:
      - id
      - zone
      - data
      - raw_data
`), &tt)
	if err != nil {
		t.Fatal(err)
	}
	encryptedValue := []byte("encrypted")
	hexEncryptedValue := hex.EncodeToString(encryptedValue)
	dataValue := "some data"
	dataHexValue := hex.EncodeToString([]byte(dataValue))
	testData := []struct {
		Query    string
		Expected string
	}{
		{Query: fmt.Sprintf(`INSERT INTO Some_Table VALUES (1, X'%s',3)`, dataHexValue), Expected: normalizeQuery(fmt.Sprintf(`INSERT INTO Some_Table VALUES (1, X'%s',3)`, hexEncryptedValue), t)},
		{Query: fmt.Sprintf(`INSERT INTO Some_Table VALUES (1, X'%s',3), (1, X'%s',3)`, dataHexValue, dataHexValue), Expected: normalizeQuery(fmt.Sprintf(`INSERT INTO Some_Table VALUES (1, X'%s',3), (1, X'%s',3)`, hexEncryptedValue, hexEncryptedValue), t)},
	}
	schemaStore := &MapTableSchemeStore{}
	schemaStore.schemas = map[string]*TableScheme{
		"Some_Table": &TableScheme{Columns: []string{"col1", "col2", "col3"}, TableName: "some_table", EncryptedColumns: []string{"col2"}},
	}
	mysqlParser, err := NewMysqlQueryParser(schemaStore)
	if err != nil {
		t.Fatal(err)
	}
	mysqlParser.encryptor = &testEncryptor{value: encryptedValue}
	for i, testCase := range testData {
		data, err := mysqlParser.Encrypt(testCase.Query)
		if err != nil {
			t.Fatal(err)
		}
		if data != testCase.Expected {
			t.Fatalf("%v. Incorrect value. Took - %s; Expected - %s;", i, data, testCase.Expected)
		}
	}
}
