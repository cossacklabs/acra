package mysql

import (
	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	base_mysql "github.com/cossacklabs/acra/decryptor/mysql/base"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/encryptor/config/common"
)

type TypeConfiguration struct {
	// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_character_set.html
	Charset      uint16
	ColumnLength uint32
	// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset_column_definition.html
	Decimal uint8
}

// TypeConfigurations contains specific info for used in TA types
var TypeConfigurations = map[base_mysql.Type]TypeConfiguration{
	base_mysql.TypeString: {
		Charset:      8,
		ColumnLength: 255,
	},
	base_mysql.TypeLong: {
		Charset:      63,
		ColumnLength: 9,
	},
	base_mysql.TypeLongLong: {
		Charset:      63,
		ColumnLength: 20,
	},
	base_mysql.TypeBlob: {
		Charset:      63,
		ColumnLength: 65535,
	},
}

var specificTypes = []base_mysql.Type{base_mysql.TypeString, base_mysql.TypeLong, base_mysql.TypeLongLong}

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
			fieldConfig, fieldConfigExist := TypeConfigurations[base_mysql.Type(newFieldType)]
			if !fieldConfigExist {
				logrus.WithField("field-type", base_mysql.Type(newFieldType)).Debug("No appropriate type configuration")
				return
			}

			field.originType = field.Type
			field.Type = base_mysql.Type(newFieldType)
			field.changed = true

			field.Charset = fieldConfig.Charset
			field.ColumnLength = fieldConfig.ColumnLength
			field.Decimal = fieldConfig.Decimal

			if field.Flag.ContainsFlag(BlobFlag) {
				for _, fieldType := range specificTypes {
					if uint16(fieldType) == uint16(newFieldType) {
						field.Flag.RemoveFlag(BlobFlag)
						return
					}
				}
			}
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
