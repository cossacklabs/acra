package base

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/utils"
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
	// AsPostgresBinary returns value encoded in postgres binary format
	AsPostgresBinary() []byte
	// AsPostgresText returns value encoded in postgres text format
	AsPostgresText() []byte

	// AsMysqlBinary returns value encoded in mysql binary format
	AsMysqlBinary() []byte
	// AsMysqlText returns value encoded in mysql text format
	AsMysqlText() []byte
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

// BytesValue is an EncodingValue that represents byte array
type BytesValue struct {
	seq []byte
}

// NewBytesValue returns EncodingValue from a byte array
func NewBytesValue(seq []byte) EncodingValue {
	return &BytesValue{seq}
}

// AsPostgresBinary returns value encoded in postgres binary format
// For a byte sequence value this is an identity operation
func (v *BytesValue) AsPostgresBinary() []byte {
	return v.seq
}

// AsPostgresText returns value encoded in postgres text format
// For a byte sequence value this is a hex encoded string
func (v *BytesValue) AsPostgresText() []byte {
	// all bytes should be encoded as valid bytea value
	return utils.PgEncodeToHex(v.seq)
}

// AsMysqlBinary returns value encoded in mysql binary format
// For a byte sequence value this is the same as text encoding
func (v *BytesValue) AsMysqlBinary() []byte {
	return v.AsMysqlText()
}

// AsMysqlText returns value encoded in mysql text format
// For a byte sequence value this is a length encoded string
func (v *BytesValue) AsMysqlText() []byte {
	return PutLengthEncodedString(v.seq)
}

// IntValue represents a {size*8}-bit integer ready for encoding
type IntValue struct {
	size     int
	value    int64
	strValue string
}

// NewIntValue returns EncodingValue from integer with size*8 bits
func NewIntValue(size int, value int64, strValue string) EncodingValue {
	return &IntValue{size, value, strValue}
}

// AsPostgresBinary returns value encoded in postgres binary format
// For an int value it is a big endian encoded integer
func (v *IntValue) AsPostgresBinary() []byte {
	newData := make([]byte, v.size)
	switch v.size {
	case 4:
		binary.BigEndian.PutUint32(newData, uint32(v.value))
	case 8:
		binary.BigEndian.PutUint64(newData, uint64(v.value))
	}
	return newData
}

// AsPostgresText returns value encoded in postgres text format
// For an int this means returning textual representation of the integer
func (v *IntValue) AsPostgresText() []byte {
	return []byte(v.strValue)
}

// AsMysqlBinary returns value encoded in mysql binary format
// For an int value it is a little endian encoded integer
func (v *IntValue) AsMysqlBinary() []byte {
	newData := make([]byte, v.size)
	switch v.size {
	case 4:
		binary.LittleEndian.PutUint32(newData, uint32(v.value))
	case 8:
		binary.LittleEndian.PutUint64(newData, uint64(v.value))
	}
	return newData
}

// AsMysqlText returns value encoded in mysql text format
// For an int this is a length encoded string of that integer
func (v *IntValue) AsMysqlText() []byte {
	return PutLengthEncodedString([]byte(v.strValue))
}

// StringValue is an EncodingValue that encodes data into string format
type StringValue struct {
	data []byte
}

// NewStringValue returns string EncodingValue
func NewStringValue(data []byte) EncodingValue {
	return &StringValue{data}
}

// AsPostgresBinary returns value encoded in postgres binary format
// In other words, it returns data as it is
func (v *StringValue) AsPostgresBinary() []byte {
	return v.data
}

// AsPostgresText returns value encoded in postgres text format
// In other words, it returns data as it is
func (v *StringValue) AsPostgresText() []byte {
	return v.data
}

// AsMysqlBinary returns value encoded in mysql binary format
// In other words, it encodes data into length encoded string
func (v *StringValue) AsMysqlBinary() []byte {
	return PutLengthEncodedString(v.data)
}

// AsMysqlText returns value encoded in mysql text format
// In other words, it encodes data into length encoded string
func (v *StringValue) AsMysqlText() []byte {
	return PutLengthEncodedString(v.data)
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

// ValueFactoryPlug is a temporary factory which will be removed when
// each backend (postgres or mysql) implements its own one
type ValueFactoryPlug struct{}

// NewStringValue creates a value that encodes as a str
func (plug *ValueFactoryPlug) NewStringValue(str []byte) EncodingValue {
	return NewStringValue(str)
}

// NewBytesValue creates a value that encodes as bytes
func (plug *ValueFactoryPlug) NewBytesValue(bytes []byte) EncodingValue {
	return NewBytesValue(bytes)
}

// NewInt32Value creates a value that encodes as int32
func (plug *ValueFactoryPlug) NewInt32Value(intVal int32, strVal []byte) EncodingValue {
	return NewIntValue(4, int64(intVal), string(strVal))
}

// NewInt64Value creates a value that encodes as int64
func (plug *ValueFactoryPlug) NewInt64Value(intVal int64, strVal []byte) EncodingValue {
	return NewIntValue(8, int64(intVal), string(strVal))
}
