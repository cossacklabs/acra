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
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/sirupsen/logrus"
	"github.com/xwb1989/sqlparser"
)

// MysqlQueryEncryptor parse query and encrypt raw data according to TableSchemaStore
type MysqlQueryEncryptor struct {
	schemaStore TableSchemaStore
	encryptor   DataEncryptor
	clientID    []byte
}

// NewMysqlQueryEncryptor create MysqlQueryEncryptor with schema and clientID
func NewMysqlQueryEncryptor(schema TableSchemaStore, clientID []byte, keystore keystore.PublicKeyStore) (*MysqlQueryEncryptor, error) {
	encryptor, err := NewAcrawriterDataEncryptor(keystore)
	if err != nil {
		return nil, err
	}
	return &MysqlQueryEncryptor{schemaStore: schema, clientID: clientID, encryptor: encryptor}, nil
}

// Encrypt raw data in query according to TableSchemaStore
func (parser *MysqlQueryEncryptor) OnQuery(query string) (string, bool, error) {
	parsed, err := sqlparser.Parse(query)
	if err != nil {
		return query, false, err
	}

	insert, ok := parsed.(*sqlparser.Insert)
	if !ok {
		return query, false, nil
	}
	tableName := sqlparser.String(insert.Table.Name)
	schema := parser.schemaStore.GetTableSchema(tableName)
	if schema == nil {
		// unsupported table, we have not schema and query hasn't columns description
		return query, false, nil
	}

	var columnsName []string
	if len(insert.Columns) > 0 {
		columnsName = make([]string, len(insert.Columns))
		for _, col := range insert.Columns {
			columnsName = append(columnsName, sqlparser.String(col))
		}
	} else if len(schema.Columns) > 0 {
		columnsName = schema.Columns
	} else {
		return query, false, nil
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
								return query, false, err
							}
							if err := base.ValidateAcraStructLength(binValue); err == nil {
								logrus.Debugln("Skip encryption for matched AcraStruct structure")
								continue
							}
							encrypted, err := parser.encryptWithColumnSettings(schema.GetColumnEncryptionSettings(columnName), binValue)
							if err != nil {
								logrus.WithError(err).Errorln("Can't encrypt hex value from query")
								return query, false, err
							}
							val.Val = []byte(hex.EncodeToString(encrypted))
						}
					}
				}
			}
		}
	}
	return sqlparser.String(insert), true, nil
}

// encryptWithColumnSettings encrypt data and use ZoneId or ClientID from ColumnEncryptionSettings if not empty otherwise static ClientID that passed to parser
func (parser *MysqlQueryEncryptor) encryptWithColumnSettings(column *ColumnEncryptionSetting, data []byte) ([]byte, error) {
	if len(column.ZoneID) > 0 {
		logrus.WithField("zone_id", column.ZoneID).Debugln("Encrypt with specific ZoneID for column")
		return parser.encryptor.EncryptWithZoneID([]byte(column.ZoneID), data)
	}
	var id []byte
	var err error
	if len(column.ClientID) > 0 {
		logrus.WithField("client_id", column.ClientID).Debugln("Encrypt with specific ClientID for column")
		id = []byte(column.ClientID)
	} else {
		logrus.WithField("client_id", parser.clientID).Debugln("Encrypt with ClientID from connection")
		id = parser.clientID
	}
	if err != nil {
		return data, err
	}
	return parser.encryptor.EncryptWithClientID(id, data)
}
