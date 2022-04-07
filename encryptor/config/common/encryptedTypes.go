package common

import (
	"errors"
	"github.com/cossacklabs/acra/pseudonymization/common"
	"strconv"
	"unicode/utf8"
)

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
	ErrUnsupportedEncryptedType = errors.New("data type not supported")
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

// ValidateDefaultValue default value according to EncryptedType
//
// str -> validates utf8 string
// bytes - do nothing
// int32/64 - try parse string as integer value with base 10
func ValidateDefaultValue(value *string, dataType EncryptedType) (err error) {
	if value == nil {
		return nil
	}
	switch dataType {
	case EncryptedType_Int32:
		_, err = strconv.ParseInt(*value, 10, 32)
		return err
	case EncryptedType_Int64:
		_, err = strconv.ParseInt(*value, 10, 64)
		return err
	case EncryptedType_String:
		if !utf8.ValidString(*value) {
			return errors.New("invalid utf8 string")
		}
		return nil
	case EncryptedType_Bytes:
		return nil
	}
	return errors.New("not supported EncryptedType")
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
