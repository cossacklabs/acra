package postgresql

import (
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/jackc/pgx/pgtype"
)

type PostgreSQLDataTypeFormat struct {
	columnInfo    base.ColumnInfo
	columnSetting config.ColumnEncryptionSetting
}

func NewPostgreSQLDataTypeFormat(columnInfo base.ColumnInfo, columnSetting config.ColumnEncryptionSetting) *PostgreSQLDataTypeFormat {
	return &PostgreSQLDataTypeFormat{
		columnInfo:    columnInfo,
		columnSetting: columnSetting,
	}
}

func (p *PostgreSQLDataTypeFormat) IsBinaryFormat() bool {
	return p.columnInfo.IsBinaryFormat()
}

func (p *PostgreSQLDataTypeFormat) IsBinaryDataOperation() bool {
	return config.IsBinaryDataOperation(p.columnSetting)
}

func mapEncryptedTypeToOID(dataType common.EncryptedType) (uint32, bool) {
	switch dataType {
	case common.EncryptedType_String:
		return pgtype.TextOID, true
	case common.EncryptedType_Int32:
		return pgtype.Int4OID, true
	case common.EncryptedType_Int64:
		return pgtype.Int8OID, true
	case common.EncryptedType_Bytes:
		return pgtype.ByteaOID, true
	}
	return 0, false
}
