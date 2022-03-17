package common

import "errors"

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
	"int32": EncryptedType_Int32,
	"int64": EncryptedType_Int64,
	"str":   EncryptedType_String,
	"bytes": EncryptedType_Bytes,
}
var supportedEncryptedTypes = map[EncryptedType]bool{
	EncryptedType_Int32:  true,
	EncryptedType_Int64:  true,
	EncryptedType_String: true,
	EncryptedType_Bytes:  true,
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
	ErrUnsupportedEncryptedType = errors.New("token type not supported")
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
