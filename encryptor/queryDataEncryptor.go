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
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/sirupsen/logrus"
	"reflect"
)

// QueryDataEncryptor parse query and encrypt raw data according to TableSchemaStore
type QueryDataEncryptor struct {
	schemaStore TableSchemaStore
	encryptor   DataEncryptor
	clientID    []byte
	dataCoder   DBDataCoder
}

// NewMysqlQueryEncryptor create QueryDataEncryptor with MySQLDBDataCoder
func NewMysqlQueryEncryptor(schema TableSchemaStore, clientID []byte, dataEncryptor DataEncryptor) (*QueryDataEncryptor, error) {
	return &QueryDataEncryptor{schemaStore: schema, clientID: clientID, encryptor: dataEncryptor, dataCoder: &MysqlDBDataCoder{}}, nil
}

// NewPostgresqlQueryEncryptor create QueryDataEncryptor with PostgresqlDBDataCoder
func NewPostgresqlQueryEncryptor(schema TableSchemaStore, clientID []byte, dataEncryptor DataEncryptor) (*QueryDataEncryptor, error) {
	return &QueryDataEncryptor{schemaStore: schema, clientID: clientID, encryptor: dataEncryptor, dataCoder: &PostgresqlDBDataCoder{}}, nil
}

// encryptInsertQuery encrypt data in insert query in VALUES and ON DUPLICATE KEY UPDATE statements
func (encryptor *QueryDataEncryptor) encryptInsertQuery(insert *sqlparser.Insert) (bool, error) {
	tableName := insert.Table.Name
	schema := encryptor.schemaStore.GetTableSchema(tableName.String())
	if schema == nil {
		// unsupported table, we have not schema and query hasn't columns description
		logrus.Debugf("Hasn't schema for table %s", tableName)
		return false, nil
	}

	var columnsName []string
	if len(insert.Columns) > 0 {
		columnsName = make([]string, 0, len(insert.Columns))
		for _, col := range insert.Columns {
			columnsName = append(columnsName, col.String())
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
					if changedValue, err := encryptor.encryptExpression(value, schema, columnName); err != nil {
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
		onDupChanged, err := encryptor.encryptUpdateExpressions(sqlparser.UpdateExprs(insert.OnDup), insert.Table, qualifierToTableMap{insert.Table.Name.String(): insert.Table.Name.String()})
		if err != nil {
			return changed, err
		}
		changed = changed || onDupChanged
	}

	return changed, nil
}

// encryptExpression check that expr is SQLVal and has Hexval then try to encrypt
func (encryptor *QueryDataEncryptor) encryptExpression(expr sqlparser.Expr, schema *TableSchema, columnName string) (bool, error) {
	if schema.NeedToEncrypt(columnName) {
		switch val := expr.(type) {
		case *sqlparser.SQLVal:
			switch val.Type {
			case sqlparser.StrVal, sqlparser.HexVal, sqlparser.PgEscapeString:
				rawData, err := encryptor.dataCoder.Decode(val)
				if err != nil {
					if err != errUnsupportedExpression {
						logrus.WithError(err).Errorln("Can't decode data")
					}
					return false, nil
				}
				if err := base.ValidateAcraStructLength(rawData); err == nil {
					logrus.Debugln("Skip encryption for matched AcraStruct structure")
					return false, nil
				}
				encrypted, err := encryptor.encryptWithColumnSettings(schema.GetColumnEncryptionSettings(columnName), rawData)
				if err != nil {
					logrus.WithError(err).Errorln("Can't encrypt hex value from query")
					return false, err
				}
				encoded, err := encryptor.dataCoder.Encode(val, encrypted)
				if err != nil {
					if err != errUnsupportedExpression {
						logrus.WithError(err).Errorln("Can't encode data")
					}
					return false, err
				}
				val.Val = encoded
				return true, nil
			}
		}
	}
	logrus.WithField("column_name", columnName).Debugln("Skip encryption for column")
	return false, nil
}

// tableData store TableName and related As value together
type tableData struct {
	TableName sqlparser.TableName
	As        sqlparser.TableIdent
}

// getTablesFromUpdate collect all tables from all update TableExprs which may be as subquery/table/join/etc
// collect only table names and ignore aliases for subqueries
func (encryptor *QueryDataEncryptor) getTablesFromUpdate(tables sqlparser.TableExprs) []*tableData {
	var outputTables []*tableData
	for _, tableExpr := range tables {
		switch statement := tableExpr.(type) {
		case *sqlparser.AliasedTableExpr:
			aliasedStatement := statement.Expr.(sqlparser.SimpleTableExpr)
			switch simpleTableStatement := aliasedStatement.(type) {
			case sqlparser.TableName:
				outputTables = append(outputTables, &tableData{TableName: simpleTableStatement, As: statement.As})
			case *sqlparser.Subquery:
				// unsupported
			default:
				logrus.Debugf("Unsupported SimpleTableExpr type %s", reflect.TypeOf(simpleTableStatement))
			}
		case *sqlparser.ParenTableExpr:
			outputTables = append(outputTables, encryptor.getTablesFromUpdate(statement.Exprs)...)
		case *sqlparser.JoinTableExpr:
			outputTables = append(outputTables, encryptor.getTablesFromUpdate(sqlparser.TableExprs{statement.LeftExpr, statement.RightExpr})...)
		default:
			logrus.Debugf("Unsupported TableExpr type %s", reflect.TypeOf(tableExpr))
		}
	}
	return outputTables
}

// hasTablesToEncrypt check that exists schema for any table in tables
func (encryptor *QueryDataEncryptor) hasTablesToEncrypt(tables []*tableData) bool {
	for _, table := range tables {
		if v := encryptor.schemaStore.GetTableSchema(table.TableName.Name.String()); v != nil {
			return true
		}
	}
	return false
}

// encryptUpdateExpressions try to encrypt all supported exprs. Use firstTable if column has not explicit table name because it's implicitly used in DBMSs
func (encryptor *QueryDataEncryptor) encryptUpdateExpressions(exprs sqlparser.UpdateExprs, firstTable sqlparser.TableName, qualifierMap qualifierToTableMap) (bool, error) {
	var schema *TableSchema
	changed := false
	for _, expr := range exprs {
		// recognize table name of column
		if expr.Name.Qualifier.IsEmpty() {
			schema = encryptor.schemaStore.GetTableSchema(firstTable.Name.String())
		} else {
			tableName := qualifierMap[expr.Name.Qualifier.Name.String()]
			schema = encryptor.schemaStore.GetTableSchema(tableName)
		}
		if schema == nil {
			continue
		}
		columnName := expr.Name.Name.String()
		if changedExpr, err := encryptor.encryptExpression(expr.Expr, schema, columnName); err != nil {
			logrus.WithError(err).Errorln("Can't encrypt update expression")
			return changed, err
		} else if changedExpr {
			changed = true
		}
	}
	return changed, nil
}

// qualifierToTableMap store table alias as key and table name as value
type qualifierToTableMap map[string]string

// encryptUpdateQuery encrypt data in Update query and return true if any fields was encrypted, false if wasn't and error if error occurred
func (encryptor *QueryDataEncryptor) encryptUpdateQuery(update *sqlparser.Update) (bool, error) {
	tables := encryptor.getTablesFromUpdate(update.TableExprs)
	if !encryptor.hasTablesToEncrypt(tables) {
		return false, nil
	}
	if len(tables) == 0 {
		return false, nil
	}
	qualifierMap := qualifierToTableMap{}
	for _, table := range tables {
		if table.As.IsEmpty() {
			qualifierMap[table.TableName.Name.String()] = table.TableName.Name.String()
		} else {
			qualifierMap[table.As.String()] = table.TableName.Name.String()
		}
	}
	firstTable := tables[0].TableName
	return encryptor.encryptUpdateExpressions(update.Exprs, firstTable, qualifierMap)
}

// OnQuery raw data in query according to TableSchemaStore
func (encryptor *QueryDataEncryptor) OnQuery(query string) (string, bool, error) {
	parsed, err := sqlparser.Parse(query)
	if err != nil {
		return query, false, err
	}
	changed := false
	switch statement := parsed.(type) {
	case *sqlparser.Insert:
		changed, err = encryptor.encryptInsertQuery(statement)
	case *sqlparser.Update:
		changed, err = encryptor.encryptUpdateQuery(statement)
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
func (encryptor *QueryDataEncryptor) encryptWithColumnSettings(column *ColumnEncryptionSetting, data []byte) ([]byte, error) {
	if len(column.ZoneID) > 0 {
		logrus.WithField("zone_id", column.ZoneID).Debugln("Encrypt with specific ZoneID for column")
		return encryptor.encryptor.EncryptWithZoneID([]byte(column.ZoneID), data)
	}
	var id []byte
	if len(column.ClientID) > 0 {
		logrus.WithField("client_id", column.ClientID).Debugln("Encrypt with specific ClientID for column")
		id = []byte(column.ClientID)
	} else {
		logrus.WithField("client_id", encryptor.clientID).Debugln("Encrypt with ClientID from connection")
		id = encryptor.clientID
	}
	return encryptor.encryptor.EncryptWithClientID(id, data)
}
