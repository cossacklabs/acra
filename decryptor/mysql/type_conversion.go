package mysql

import (
	"github.com/cossacklabs/acra/encryptor/config/common"
)

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
