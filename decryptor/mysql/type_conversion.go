package mysql

import (
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/encryptor/config/common"
)

// updatedFieldEncodedType change the field type according to provided DataType
func updatedFieldEncodedType(field *ColumnDescription, schemaStore config.TableSchemaStore) {
	tableSchema := schemaStore.GetTableSchema(string(field.Table))
	if tableSchema == nil {
		return
	}

	if setting := tableSchema.GetColumnEncryptionSettings(string(field.Name)); setting != nil {
		newFieldType, ok := mapEncryptedTypeToField(setting.GetEncryptedDataType())
		if ok {
			field.originType = field.Type
			field.Type = Type(newFieldType)
			field.changed = true
		}
	}
}

// mapEncryptedTypeToField convert EncryptedType to mysql related type
func mapEncryptedTypeToField(dataType common.EncryptedType) (Type, bool) {
	switch dataType {
	case common.EncryptedType_String:
		return TypeString, true
	case common.EncryptedType_Int32:
		return TypeLong, true
	case common.EncryptedType_Int64:
		return TypeLongLong, true
	case common.EncryptedType_Bytes:
		return TypeBlob, true
	}
	return 0, false
}
