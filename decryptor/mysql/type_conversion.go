package mysql

import (
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	base_mysql "github.com/cossacklabs/acra/decryptor/mysql/base"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/encryptor/config/common"
)

// DataTypeFormat implementation of type_awareness.DataTypeFormat for PostgreSQL
type DataTypeFormat struct {
	columnInfo    base.ColumnInfo
	columnSetting config.ColumnEncryptionSetting
}

// NewDataTypeFormat create new DataTypeFormat from ColumnInfo and ColumnEncryptionSetting
func NewDataTypeFormat(columnInfo base.ColumnInfo, columnSetting config.ColumnEncryptionSetting) *DataTypeFormat {
	return &DataTypeFormat{
		columnInfo:    columnInfo,
		columnSetting: columnSetting,
	}
}

// IsBinaryFormat check if columnInfo is binary
func (p *DataTypeFormat) IsBinaryFormat() bool {
	return p.columnInfo.IsBinaryFormat()
}

// IsBinaryDataOperation check from columnSetting if binaryOperation
func (p *DataTypeFormat) IsBinaryDataOperation() bool {
	return config.IsBinaryDataOperation(p.columnSetting)
}

// GetDefaultDataValue return DefaultDataValue
func (p *DataTypeFormat) GetDefaultDataValue() *string {
	return p.columnSetting.GetDefaultDataValue()
}

// GetDBDataTypeID return DBDataTypeID
func (p *DataTypeFormat) GetDBDataTypeID() uint32 {
	return p.columnSetting.GetDBDataTypeID()
}

// GetResponseOnFail return ResponseOnFail
func (p *DataTypeFormat) GetResponseOnFail() common.ResponseOnFail {
	return p.columnSetting.GetResponseOnFail()
}

// GetColumnName return ColumnName
func (p *DataTypeFormat) GetColumnName() string {
	return p.columnSetting.ColumnName()
}

// updateFieldEncodedType change the field type according to provided DataType
func updateFieldEncodedType(field *ColumnDescription, schemaStore config.TableSchemaStore) {
	tableSchema := schemaStore.GetTableSchema(string(field.Table))
	if tableSchema == nil {
		return
	}

	if setting := tableSchema.GetColumnEncryptionSettings(string(field.Name)); setting != nil {
		newFieldType, ok := mapEncryptedTypeToField(setting.GetDBDataTypeID())
		if ok {
			field.originType = field.Type
			field.Type = base_mysql.Type(newFieldType)
			field.changed = true
		}
	}
}

// mapEncryptedTypeToField convert EncryptedType to mysql related type
func mapEncryptedTypeToField(dataTypeID uint32) (uint32, bool) {
	mysqlEncoders := type_awareness.GetMySQLDataTypeIDEncoders()
	if _, ok := mysqlEncoders[dataTypeID]; !ok {
		return 0, false
	}

	return dataTypeID, true
}
