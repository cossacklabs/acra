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
	"reflect"
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

// encryptInsertQuery encrypt data in insert query in VALUES and ON DUPLICATE KEY UPDATE statements
func (parser *MysqlQueryEncryptor) encryptInsertQuery(insert *sqlparser.Insert) (bool, error) {
	tableName := sqlparser.String(insert.Table.Name)
	schema := parser.schemaStore.GetTableSchema(tableName)
	if schema == nil {
		// unsupported table, we have not schema and query hasn't columns description
		return false, nil
	}

	var columnsName []string
	if len(insert.Columns) > 0 {
		columnsName = make([]string, 0, len(insert.Columns))
		for _, col := range insert.Columns {
			columnsName = append(columnsName, sqlparser.String(col))
		}
	} else if len(schema.Columns) > 0 {
		columnsName = schema.Columns
	}

	changed := false

	if len(columnsName) > 0 {
		switch rows := insert.Rows.(type) {
		case sqlparser.Values:
			for _, valTuple := range rows {
				// collect values per column
				for j, value := range valTuple {
					columnName := columnsName[j]
					if changedValue, err := parser.encryptExpression(value, schema, columnName); err != nil {
						logrus.WithError(err).Errorln("Can't encrypt expression")
						return changed, err
					} else if changedValue {
						changed = true
					}
				}
			}
		}
	}

	if len(insert.OnDup) > 0 {
		onDupChanged, err := parser.encryptUpdateExpressions(sqlparser.UpdateExprs(insert.OnDup), insert.Table)
		if err != nil {
			return changed, err
		}
		changed = changed || onDupChanged
	}

	return changed, nil
}

// encryptExpression check that expr is SQLVal and has Hexval then try to encrypt
func (parser *MysqlQueryEncryptor) encryptExpression(expr sqlparser.Expr, schema *TableSchema, columnName string) (bool, error) {
	if schema.NeedToEncrypt(columnName) {
		switch val := expr.(type) {
		case *sqlparser.SQLVal:
			switch val.Type {
			case sqlparser.HexVal:
				binValue := make([]byte, hex.DecodedLen(len(val.Val)))
				_, err := hex.Decode(binValue, val.Val)
				if err != nil {
					logrus.WithError(err).Errorln("Can't decode hex string literal")
					return false, err
				}
				if err := base.ValidateAcraStructLength(binValue); err == nil {
					logrus.Debugln("Skip encryption for matched AcraStruct structure")
					return false, nil
				}
				encrypted, err := parser.encryptWithColumnSettings(schema.GetColumnEncryptionSettings(columnName), binValue)
				if err != nil {
					logrus.WithError(err).Errorln("Can't encrypt hex value from query")
					return false, err
				}
				val.Val = []byte(hex.EncodeToString(encrypted))
				return true, nil
			}
		}
	}
	return false, nil
}

// getTablesFromUpdate collect all tables from all update TableExprs which may be as subquery/table/join/etc
// collect only table names and ignore aliases for subqueries
func (parser *MysqlQueryEncryptor) getTablesFromUpdate(tables sqlparser.TableExprs) sqlparser.TableNames {
	var outputTables sqlparser.TableNames
	for _, tableExpr := range tables {
		switch statement := tableExpr.(type) {
		case *sqlparser.AliasedTableExpr:
			aliasedStatement := statement.Expr.(sqlparser.SimpleTableExpr)
			switch simpleTableStatement := aliasedStatement.(type) {
			case sqlparser.TableName:
				outputTables = append(outputTables, simpleTableStatement)
			case *sqlparser.Subquery:
				// unsupported
			default:
				logrus.Debugf("Unsupported SimpleTableExpr type %s", reflect.TypeOf(simpleTableStatement))
			}
		case *sqlparser.ParenTableExpr:
			outputTables = append(outputTables, parser.getTablesFromUpdate(statement.Exprs)...)
		case *sqlparser.JoinTableExpr:
			outputTables = append(outputTables, parser.getTablesFromUpdate(sqlparser.TableExprs{statement.LeftExpr, statement.RightExpr})...)
		default:
			logrus.Debugf("Unsupported TableExpr type %s", reflect.TypeOf(tableExpr))
		}
	}
	return outputTables
}

// hasTablesToEncrypt check that exists schema for any table in tables
func (parser *MysqlQueryEncryptor) hasTablesToEncrypt(tables sqlparser.TableNames) bool {
	for _, table := range tables {
		if v := parser.schemaStore.GetTableSchema(table.Name.String()); v != nil {
			return true
		}
	}
	return false
}

// encryptUpdateExpressions try to encrypt all supported exprs. Use firstTable if column has not explicit table name because it's implicitly used in DBMSs
func (parser *MysqlQueryEncryptor) encryptUpdateExpressions(exprs sqlparser.UpdateExprs, firstTable sqlparser.TableName) (bool, error) {
	var schema *TableSchema
	changed := false
	for _, expr := range exprs {
		// recognize table name of column
		if expr.Name.Qualifier.IsEmpty() {
			schema = parser.schemaStore.GetTableSchema(firstTable.Name.String())
		} else {
			schema = parser.schemaStore.GetTableSchema(expr.Name.Qualifier.Name.String())
		}
		if schema == nil {
			continue
		}
		columnName := expr.Name.Name.String()
		if changedExpr, err := parser.encryptExpression(expr.Expr, schema, columnName); err != nil {
			logrus.WithError(err).Errorln("Can't encrypt update expression")
			return changed, err
		} else if changedExpr {
			changed = true
		}
	}
	return changed, nil
}

// encryptUpdateQuery encrypt data in Update query and return true if any fields was encrypted, false if wasn't and error if error occurred
func (parser *MysqlQueryEncryptor) encryptUpdateQuery(update *sqlparser.Update) (bool, error) {
	tables := parser.getTablesFromUpdate(update.TableExprs)
	if !parser.hasTablesToEncrypt(tables) {
		return false, nil
	}
	if len(tables) == 0 {
		return false, nil
	}
	firstTable := tables[0]
	return parser.encryptUpdateExpressions(update.Exprs, firstTable)
}

// Encrypt raw data in query according to TableSchemaStore
func (parser *MysqlQueryEncryptor) OnQuery(query string) (string, bool, error) {
	parsed, err := sqlparser.Parse(query)
	if err != nil {
		return query, false, err
	}
	changed := false
	switch statement := parsed.(type) {
	case *sqlparser.Insert:
		changed, err = parser.encryptInsertQuery(statement)
	case *sqlparser.Update:
		changed, err = parser.encryptUpdateQuery(statement)
	}
	if err != nil {
		return query, false, err
	}
	if changed {
		return sqlparser.String(parsed), true, nil
	}
	return query, false, nil
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
