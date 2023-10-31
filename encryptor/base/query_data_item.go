package base

import (
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/sqlparser"
)

// AliasToTableMap store table alias as key and table name as value
type AliasToTableMap map[string]string

// AliasedTableName store TableName and related As value together
type AliasedTableName struct {
	TableName sqlparser.TableName
	As        sqlparser.TableIdent
}

// NewAliasToTableMapFromTables create AliasToTableMap from slice of aliased tables
func NewAliasToTableMapFromTables(tables []*AliasedTableName) AliasToTableMap {
	qualifierMap := AliasToTableMap{}
	for _, table := range tables {
		if table.As.IsEmpty() {
			qualifierMap[table.TableName.Name.ValueForConfig()] = table.TableName.Name.ValueForConfig()
		} else {
			qualifierMap[table.As.ValueForConfig()] = table.TableName.Name.ValueForConfig()
		}
	}
	return qualifierMap
}

// QueryDataItem stores information about table column and encryption setting
type QueryDataItem struct {
	setting     config.ColumnEncryptionSetting
	tableName   string
	columnName  string
	columnAlias string
}

// NewQueryDataItem create new QueryDataItem
func NewQueryDataItem(setting config.ColumnEncryptionSetting, tableName, columnName, columnAlias string) *QueryDataItem {
	return &QueryDataItem{
		setting:     setting,
		tableName:   tableName,
		columnName:  columnName,
		columnAlias: columnAlias,
	}
}

// Setting return associated ColumnEncryptionSetting or nil if not found
func (q *QueryDataItem) Setting() config.ColumnEncryptionSetting {
	return q.setting
}

// TableName return table name associated with item or empty string if it is not related to any table, or not recognized
func (q *QueryDataItem) TableName() string {
	return q.tableName
}

// ColumnName return column name if it was matched to any
func (q *QueryDataItem) ColumnName() string {
	return q.columnName
}

// ColumnAlias if matched as alias to any data item
func (q *QueryDataItem) ColumnAlias() string {
	return q.columnAlias
}
