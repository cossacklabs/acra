package postgresql

import (
	"github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/jackc/pgx/pgtype"
)

func mapEncryptedTypeToOID(dataType common.EncryptedType) (uint32, bool) {
	switch dataType {
	case common.EncryptedType_String:
		return pgtype.TextOID, true
	case common.EncryptedType_Int32:
		return pgtype.Int4OID, true
	case common.EncryptedType_Int64:
		return pgtype.Int8OID, true
	}
	return 0, false
}
