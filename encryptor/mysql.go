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
	"github.com/sirupsen/logrus"
	"github.com/xwb1989/sqlparser"
)

type MysqlQueryParser struct {
	schemaStore TableSchemeStore
	encryptor   DataEncryptor
}

func NewMysqlQueryParser(schema TableSchemeStore) (*MysqlQueryParser, error) {
	return &MysqlQueryParser{schemaStore: schema}, nil
}

func (parser *MysqlQueryParser) Encrypt(query string) (string, error) {
	parsed, err := sqlparser.Parse(query)
	if err != nil {
		return "", err
	}

	insert, ok := parsed.(*sqlparser.Insert)
	if !ok {
		return query, nil
	}
	tableName := sqlparser.String(insert.Table.Name)
	schema := parser.schemaStore.GetTableSchema(tableName)
	if schema == nil {
		// unsupported table, we have not schema and query hasn't columns description
		return query, nil
	}

	var columnsName []string
	if len(insert.Columns) > 0 {
		columnsName = make([]string, len(insert.Columns))
		for _, col := range insert.Columns {
			columnsName = append(columnsName, sqlparser.String(col))
		}
	} else {
		columnsName = schema.Columns

	}

	switch rows := insert.Rows.(type) {
	case sqlparser.Values:
		for _, valTuple := range rows {
			// collect values per column
			for j, value := range valTuple {
				columnName := columnsName[j]
				if schema.NeedToEncrypt(columnName) {
					switch val := value.(type) {
					case *sqlparser.SQLVal:
						switch val.Type {
						case sqlparser.HexVal:
							binValue := make([]byte, hex.DecodedLen(len(val.Val)))
							_, err := hex.Decode(binValue, val.Val)
							if err != nil {
								logrus.WithError(err).Errorln("Can't decode hex string literal")
								return "", err
							}
							encrypted, err := parser.encryptor.Encrypt(binValue)
							if err != nil {
								logrus.WithError(err).Errorln("Can't encrypt hex value from query")
								return "", err
							}
							val.Val = []byte(hex.EncodeToString(encrypted))
						}
					}
				}
			}
		}
	}
	return sqlparser.String(insert), nil
}
