package postgresql

import (
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
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

func mapEncryptedTypeToOID(dataTypeID uint32) (uint32, bool) {
	pgsqlEncoders := type_awareness.GetPostgreSQLDataTypeIDEncoders()
	if _, ok := pgsqlEncoders[dataTypeID]; !ok {
		return 0, false
	}

	return dataTypeID, true
}
