package common

import (
	"errors"
	"fmt"

	"github.com/cossacklabs/acra/decryptor/mysql/base"
	"github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/jackc/pgx/pgtype"
)

// ResponseOnFail represents possible values for `response_on_fail` field
type ResponseOnFail string

const (
	// ResponseOnFailEmpty occurs as a default value of fresh settings
	// Should be treated in the same way as ResponseOnFail_Ciphertext
	// TODO: maybe then hide this conversion under the call of
	//       `GetResponseOnFail`
	ResponseOnFailEmpty ResponseOnFail = ""

	// ResponseOnFailCiphertext indicates that raw ciphertext value should be returned
	// as is.
	ResponseOnFailCiphertext ResponseOnFail = "ciphertext"

	// ResponseOnFailDefault indicates that default value should be returned
	// instead of failed one.
	ResponseOnFailDefault ResponseOnFail = "default_value"

	// ResponseOnFailError indicates that db-specific error should be returned
	// to a client
	ResponseOnFailError ResponseOnFail = "error"
)

// MySQLEncryptedTypeDataTypeIDs used for mapping EncryptedType with MySQL Types
var MySQLEncryptedTypeDataTypeIDs = map[EncryptedType]uint32{
	EncryptedType_Int32:  uint32(base.TypeLong),
	EncryptedType_Int64:  uint32(base.TypeLongLong),
	EncryptedType_String: uint32(base.TypeString),
	EncryptedType_Bytes:  uint32(base.TypeBlob),
}

// PostgreSQLEncryptedTypeDataTypeIDs used for mapping EncryptedType with PostgreSQL OIDs
var PostgreSQLEncryptedTypeDataTypeIDs = map[EncryptedType]uint32{
	EncryptedType_Int32:  pgtype.Int4OID,
	EncryptedType_Int64:  pgtype.Int8OID,
	EncryptedType_String: pgtype.TextOID,
	EncryptedType_Bytes:  pgtype.ByteaOID,
}

// MySQLDataTypeIDEncryptedType used for mapping MySQL Types OIDs with DataType
var MySQLDataTypeIDEncryptedType = map[uint32]string{
	uint32(base.TypeLong):     "int32",
	uint32(base.TypeLongLong): "int64",
	uint32(base.TypeString):   "str",
	uint32(base.TypeBlob):     "bytes",
}

// PostgreSQLDataTypeIDEncryptedType used for mapping PostgreSQL OIDs with DataType
var PostgreSQLDataTypeIDEncryptedType = map[uint32]string{
	pgtype.Int4OID:  "int32",
	pgtype.Int8OID:  "int64",
	pgtype.TextOID:  "str",
	pgtype.ByteaOID: "bytes",
}

// ParseStringEncryptedType parse string value to EncryptedType value
func ParseStringEncryptedType(value string) (EncryptedType, error) {
	parsed, ok := encryptedTypeNames[value]
	if !ok {
		return EncryptedType_Unknown, ErrUnknownEncryptedType
	}
	return parsed, nil
}

// Data type names as expected in the configuration file.
var encryptedTypeNames = map[string]EncryptedType{
	"int32":   EncryptedType_Int32,
	"int64":   EncryptedType_Int64,
	"str":     EncryptedType_String,
	"bytes":   EncryptedType_Bytes,
	"Unknown": EncryptedType_Unknown,
}
var supportedEncryptedTypes = map[EncryptedType]bool{
	EncryptedType_Int32:   true,
	EncryptedType_Int64:   true,
	EncryptedType_String:  true,
	EncryptedType_Bytes:   true,
	EncryptedType_Unknown: true,
}

// ToConfigString converts value to string used in encryptor_config
func (x EncryptedType) ToConfigString() (val string, err error) {
	err = ErrUnknownEncryptedType
	switch x {
	case EncryptedType_Int32:
		return "int32", nil
	case EncryptedType_Int64:
		return "int64", nil
	case EncryptedType_String:
		return "str", nil
	case EncryptedType_Bytes:
		return "bytes", nil
	}
	return
}

// Validation errors
var (
	ErrUnknownEncryptedType     = errors.New("unknown token type")
	ErrUnsupportedDBDataTypeID  = errors.New("unsupported DB data type id")
	ErrUnsupportedEncryptedType = errors.New("data type not supported")
	ErrDataTypeWithDataTypeID   = errors.New("data_type can`t be used along with data_type_db_identifier option")
	ErrUnsupportedDataTypeID    = errors.New("unsupported data_type_db_identifier option")
)

// ValidateEncryptedType return true if value is supported EncryptedType
func ValidateEncryptedType(value EncryptedType) error {
	supported, ok := supportedEncryptedTypes[value]
	if !ok {
		return ErrUnknownEncryptedType
	}
	if !supported {
		return ErrUnsupportedEncryptedType
	}
	return nil
}

// TokenTypeToEncryptedDataType converts value to appropriate EncryptedType
func TokenTypeToEncryptedDataType(tokenType common.TokenType) EncryptedType {
	switch tokenType {
	case common.TokenType_Int32:
		return EncryptedType_Int32
	case common.TokenType_Int64:
		return EncryptedType_Int64
	case common.TokenType_String, common.TokenType_Email:
		return EncryptedType_String
	case common.TokenType_Bytes:
		return EncryptedType_Bytes
	}
	return EncryptedType_Unknown
}

// ValidateOnFail returns error if `response_on_fail` value is not supported
func ValidateOnFail(value ResponseOnFail) (err error) {
	switch value {
	case ResponseOnFailEmpty,
		ResponseOnFailCiphertext,
		ResponseOnFailDefault,
		ResponseOnFailError:
		return nil
	}
	return fmt.Errorf("unknown response_on_fail value: '%s'", value)
}
