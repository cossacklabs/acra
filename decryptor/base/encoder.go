package base

import (
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/encryptor/config/common"
)

// EncodingError is returned from encoding handlers when some failure occurs.
// This error should be sent to the user directly, so it needs to be own type
// to be distinguishable.
type EncodingError struct {
	column string
}

func (e *EncodingError) Error() string {
	return fmt.Sprintf("encoding error in column %q", e.column)
}

// Is checks if err is the same as target error.
// It checks the type and the `.column` field.
// Used in tests to provide functionality of `errors.Is`
func (e *EncodingError) Is(err error) bool {
	encErr, ok := err.(*EncodingError)
	if !ok {
		return false
	}
	return encErr.column == e.column
}

// NewEncodingError returns new EncodingError with specified column
func NewEncodingError(column string) error {
	return &EncodingError{column}
}

// EncodingValue represents a (possibly parsed and prepared) value that is
// ready to be encoded
type EncodingValue interface {
	// AssBinary returns value encoded in a binary format
	AsBinary() []byte
	// AsText returns value encoded in a text format
	AsText() []byte
}

// EncodingValueFactory represents a factory that produces ready for encoding
// value.
type EncodingValueFactory interface {
	// NewStringValue creates a value that encodes as a str
	NewStringValue(str []byte) EncodingValue
	// NewBytesValue creates a value that encodes as bytes
	NewBytesValue(bytes []byte) EncodingValue
	// NewInt32Value creates a value that encodes as int32
	NewInt32Value(intVal int32, strVal []byte) EncodingValue
	// NewInt64Value creates a value that encodes as int64
	NewInt64Value(intVal int64, strVal []byte) EncodingValue
}

// EncodeDefault returns wrapped default value from settings ready for encoding
// returns nil if something went wrong, which in many cases indicates that the
// original value should be returned as it is
func EncodeDefault(setting config.ColumnEncryptionSetting, valueFactory EncodingValueFactory, logger *logrus.Entry) EncodingValue {
	strValue := setting.GetDefaultDataValue()
	if strValue == nil {
		logger.Errorln("Default value is not specified")
		return nil
	}

	dataType := setting.GetEncryptedDataType()

	switch dataType {
	case common.EncryptedType_String:
		return valueFactory.NewStringValue([]byte(*strValue))
	case common.EncryptedType_Bytes:
		binValue, err := base64.StdEncoding.DecodeString(*strValue)
		if err != nil {
			logger.WithError(err).Errorln("Can't decode base64 default value")
			return nil
		}
		return valueFactory.NewBytesValue(binValue)
	case common.EncryptedType_Int32, common.EncryptedType_Int64:
		size := 64
		if dataType == common.EncryptedType_Int32 {
			size = 32
		}
		value, err := strconv.ParseInt(*strValue, 10, size)
		if err != nil {
			logger.WithError(err).Errorln("Can't parse default integer value")
			return nil
		}

		if dataType == common.EncryptedType_Int32 {
			return valueFactory.NewInt32Value(int32(value), []byte(*strValue))
		}
		return valueFactory.NewInt64Value(value, []byte(*strValue))
	}
	return nil
}

// EncodeOnFail returns either an error, which should be returned, or value, which
// should be encoded, because there is some problem with original, or `nil`
// which indicates that original value should be returned as is.
func EncodeOnFail(setting config.ColumnEncryptionSetting, valueFactory EncodingValueFactory, logger *logrus.Entry) (EncodingValue, error) {
	action := setting.GetResponseOnFail()
	switch action {
	case common.ResponseOnFailEmpty, common.ResponseOnFailCiphertext:
		return nil, nil

	case common.ResponseOnFailDefault:
		return EncodeDefault(setting, valueFactory, logger), nil

	case common.ResponseOnFailError:
		return nil, NewEncodingError(setting.ColumnName())
	}

	return nil, fmt.Errorf("unknown action: %q", action)
}
