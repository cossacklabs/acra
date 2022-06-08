package mysql

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strconv"

	"github.com/cossacklabs/acra/utils"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/cossacklabs/acra/logging"
	"github.com/sirupsen/logrus"
)

// ErrConvertToDataType error that indicates if data type conversion was failed
var ErrConvertToDataType = errors.New("error on converting to data type")

var valueFactory base.EncodingValueFactory = &mysqlValueFactory{}

// BaseMySQLDataProcessor implements processor and encode/decode binary intX values to text format which acceptable by Tokenizer
type BaseMySQLDataProcessor struct{}

// DataEncoderProcessor implements processor and encode/decode binary intX values to text format which acceptable by Tokenizer
type DataEncoderProcessor struct {
	BaseMySQLDataProcessor
}

// NewDataEncoderProcessor return new data encoder from/to binary format for tokenization
func NewDataEncoderProcessor() *DataEncoderProcessor {
	return &DataEncoderProcessor{
		BaseMySQLDataProcessor{},
	}
}

// ID return name of processor
func (p *DataEncoderProcessor) ID() string {
	return "DataEncoderProcessor"
}

// DataDecoderProcessor implements processor and encode/decode binary intX values to text format which acceptable by Tokenizer
type DataDecoderProcessor struct {
	BaseMySQLDataProcessor
}

// NewDataDecoderProcessor return new data encoder from/to binary format for tokenization
func NewDataDecoderProcessor() *DataDecoderProcessor {
	return &DataDecoderProcessor{
		BaseMySQLDataProcessor{},
	}
}

// ID return name of processor
func (p *DataDecoderProcessor) ID() string {
	return "DataDecoderProcessor"
}

// here we process encryption/tokenization results before send it to a client
// acra decrypts or de-tokenize SQL literals, so we should convert string SQL literals to binary format
// if client expects int, then parse INT literals and convert to binary 4/8 byte format
// if expects bytes, then pass as is
// if expects string, then leave as is if it is valid string or encode to hex
// if it is encrypted data then we return default values or as is if applicable (binary data)
func (p *BaseMySQLDataProcessor) encodeBinary(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	logger = logger.WithField("column", setting.ColumnName()).WithField("decrypted", base.IsDecryptedFromContext(ctx))
	logger.Debugln("Encode binary")

	if len(data) == 0 {
		// we still need to encode result data as it might be null field in db
		return ctx, PutLengthEncodedString(data), nil
	}

	encodingValue, err := p.encodeValueWithDataType(ctx, data, setting, logger)
	if err != nil && err != ErrConvertToDataType {
		return nil, nil, err
	}

	// in case of successful encoding with defined data type return encoded data
	if encodingValue != nil {
		return ctx, encodingValue.AsBinary(), nil
	}

	var columnType = columnInfo.DataBinaryType()
	// in case of error on converting to defined type we should roll back field type and encode it as it was originally
	if err == ErrConvertToDataType {
		ctx = base.MarkErrorConvertedDataTypeContext(ctx)
		columnType = columnInfo.OriginBinaryType()
	}

	var encoded []byte
	// After processing, parse the value back and reencode it. Take care for the format to match.
	// The result must have exact same format as it had. Overflows are unacceptable.
	switch Type(columnType) {
	case TypeNull:
		if data != nil {
			return nil, nil, errors.New("NULL not kept NULL")
		}

	case TypeTiny:
		encoded = make([]byte, 1)
		intValue, err := strconv.ParseInt(utils.BytesToString(data), 10, 8)
		if err != nil {
			return nil, nil, err
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int8(intValue))
		return ctx, encoded, err

	case TypeShort, TypeYear:
		encoded = make([]byte, 2)
		intValue, err := strconv.ParseInt(utils.BytesToString(data), 10, 16)
		if err != nil {
			return nil, nil, err
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int16(intValue))
		return ctx, encoded, err

	case TypeInt24, TypeLong:
		encoded = make([]byte, 4)
		intValue, err := strconv.ParseInt(utils.BytesToString(data), 10, 32)
		if err != nil {
			return nil, nil, err
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int32(intValue))
		return ctx, encoded, err

	case TypeLongLong:
		encoded = make([]byte, 8)
		intValue, err := strconv.ParseInt(utils.BytesToString(data), 10, 64)
		if err != nil {
			return nil, nil, err
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int64(intValue))
		return ctx, encoded, err

	case TypeFloat:
		encoded = make([]byte, 4)
		floatValue, err := strconv.ParseFloat(utils.BytesToString(data), 32)
		if err != nil {
			return nil, nil, err
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, float32(floatValue))
		return ctx, encoded, err

	case TypeDouble:
		encoded = make([]byte, 8)
		floatValue, err := strconv.ParseFloat(utils.BytesToString(data), 64)
		if err != nil {
			return nil, nil, err
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, floatValue)
		return ctx, encoded, err
	}

	return ctx, PutLengthEncodedString(data), nil
}

func (p *BaseMySQLDataProcessor) encodeValueWithDataType(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, logger *logrus.Entry) (base.EncodingValue, error) {
	dataType := setting.GetEncryptedDataType()
	switch dataType {
	case common.EncryptedType_String, common.EncryptedType_Bytes:
		if !base.IsDecryptedFromContext(ctx) {
			value, err := base.EncodeOnFail(setting, &mysqlValueFactory{}, logger)
			if err != nil {
				return nil, err
			} else if value != nil {
				return value, nil
			}
			return nil, ErrConvertToDataType
		}
		return nil, nil
	case common.EncryptedType_Int32, common.EncryptedType_Int64:
		strValue := utils.BytesToString(data)
		intValue, err := strconv.ParseInt(strValue, 10, 64)
		// if it's valid string literal and decrypted, return as is
		if err == nil {
			if dataType == common.EncryptedType_Int32 {
				return valueFactory.NewInt32Value(int32(intValue), data), nil
			}
			return valueFactory.NewInt64Value(intValue, data), nil
		}
		// if it's encrypted binary, then it is binary array that is invalid int literal
		if !base.IsDecryptedFromContext(ctx) {
			value, err := base.EncodeOnFail(setting, valueFactory, logger)
			if err != nil {
				return nil, err
			} else if value != nil {
				return value, nil
			}
			return nil, ErrConvertToDataType
		}
	}

	return nil, nil
}

func (p *BaseMySQLDataProcessor) encodeText(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	logger = logger.WithField("column", setting.ColumnName()).WithField("decrypted", base.IsDecryptedFromContext(ctx))
	logger.Debugln("Encode text")
	if len(data) == 0 {
		// we still need to encode result data as it might be null field in db
		return ctx, PutLengthEncodedString(data), nil
	}

	encodingValue, err := p.encodeValueWithDataType(ctx, data, setting, logger)
	if err != nil && err != ErrConvertToDataType {
		return nil, nil, err
	}

	// in case of successful encoding with defined data type return encoded data
	if encodingValue != nil {
		return ctx, encodingValue.AsText(), nil
	}

	// in case of error on converting to defined type we should roll back field type and encode it as it was originally
	if err == ErrConvertToDataType {
		ctx = base.MarkErrorConvertedDataTypeContext(ctx)
	}

	return ctx, PutLengthEncodedString(data), nil
}

func (p *BaseMySQLDataProcessor) decodeBinary(ctx context.Context, encoded []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	// convert from binary to text literal because tokenizer expects int value as string literal
	columnType := columnInfo.DataBinaryType()
	if originType := columnInfo.OriginBinaryType(); originType != 0 {
		columnType = originType
	}

	switch Type(columnType) {
	case TypeNull:
		// do nothing

	case TypeTiny:
		var numericValue int8
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, strconv.AppendInt(nil, int64(numericValue), 10), nil

	case TypeShort, TypeYear:
		var numericValue int16
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, strconv.AppendInt(nil, int64(numericValue), 10), nil

	case TypeInt24, TypeLong:
		var numericValue int32
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, strconv.AppendInt(nil, int64(numericValue), 10), nil

	case TypeLongLong:
		var numericValue int64
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, strconv.AppendInt(nil, int64(numericValue), 10), nil

	case TypeFloat:
		var numericValue float32
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, strconv.AppendFloat(nil, float64(numericValue), 'G', -1, 32), nil

	case TypeDouble:
		var numericValue float64
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, strconv.AppendFloat(nil, numericValue, 'G', -1, 32), nil
	}
	// binary and string values in binary format we return as is because it is encrypted blob
	return ctx, encoded, nil
}

// OnColumn encode binary value to text and back. Should be before and after tokenizer processor
func (p *DataEncoderProcessor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	columnSetting, ok := encryptor.EncryptionSettingFromContext(ctx)
	if !ok {
		// for case when data encrypted with acrastructs on app's side and used without any encryption setting
		columnSetting = &config.BasicColumnEncryptionSetting{}
	}
	logger := logging.GetLoggerFromContext(ctx)
	columnInfo, ok := base.ColumnInfoFromContext(ctx)
	if !ok {
		logger.WithField("processor", "MySQLDataEncoderProcessor").Warningln("No column info in ctx")
		// we can't do anything
		return ctx, data, nil
	}
	if columnInfo.IsBinaryFormat() {
		return p.encodeBinary(ctx, data, columnSetting, columnInfo, logger)
	}
	return p.encodeText(ctx, data, columnSetting, columnInfo, logger)
}

// OnColumn encode binary value to text and back. Should be before and after tokenizer processor
func (p *DataDecoderProcessor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	columnSetting, ok := encryptor.EncryptionSettingFromContext(ctx)
	if !ok {
		// for case when data encrypted with acrastructs on app's side and used without any encryption setting
		columnSetting = &config.BasicColumnEncryptionSetting{}
	}
	logger := logging.GetLoggerFromContext(ctx)
	columnInfo, ok := base.ColumnInfoFromContext(ctx)
	if !ok {
		logger.WithField("processor", "MySQLDataDecoderProcessor").Warningln("No column info in ctx")
		// we can't do anything
		return ctx, data, nil
	}

	if columnInfo.IsBinaryFormat() {
		return p.decodeBinary(ctx, data, columnSetting, columnInfo, logger)
	}
	return ctx, data, nil
}

// bytesValue is an EncodingValue that represents byte array
type bytesValue struct {
	bytes []byte
}

// AsBinary returns value encoded in mysql binary format
// For a byte sequence value this is the same as text encoding
func (v *bytesValue) AsBinary() []byte {
	return v.AsText()
}

// AsText returns value encoded in mysql text format
// For a byte sequence value this is a length encoded string
func (v *bytesValue) AsText() []byte {
	return PutLengthEncodedString(v.bytes)
}

// intValue represents a {size*8}-bit integer ready for encoding
type intValue struct {
	size     int
	intValue int64
	strValue []byte
}

// AsBinary returns value encoded in mysql binary format
// For an int value it is a little endian encoded integer
func (v *intValue) AsBinary() []byte {
	newData := make([]byte, v.size)
	switch v.size {
	case 4:
		binary.LittleEndian.PutUint32(newData, uint32(v.intValue))
	case 8:
		binary.LittleEndian.PutUint64(newData, uint64(v.intValue))
	}
	return newData
}

// AsText returns value encoded in mysql text format
// For an int this is a length encoded string of that integer
func (v *intValue) AsText() []byte {
	return PutLengthEncodedString(v.strValue)
}

// stringValue is an EncodingValue that encodes data into string format
type stringValue struct {
	data []byte
}

// AsBinary returns value encoded in mysql binary format
// In other words, it encodes data into length encoded string
func (v *stringValue) AsBinary() []byte {
	return PutLengthEncodedString(v.data)
}

// AsText returns value encoded in mysql text format
// In other words, it encodes data into length encoded string
func (v *stringValue) AsText() []byte {
	return PutLengthEncodedString(v.data)
}

// mysqlValueFactory is a factory that produces values that can encode into
// mysql format
type mysqlValueFactory struct{}

// NewStringValue creates a value that encodes as a str
func (*mysqlValueFactory) NewStringValue(str []byte) base.EncodingValue {
	return &stringValue{data: str}
}

// NewBytesValue creates a value that encodes as bytes
func (*mysqlValueFactory) NewBytesValue(bytes []byte) base.EncodingValue {
	return &bytesValue{bytes}
}

// NewInt32Value creates a value that encodes as int32
func (*mysqlValueFactory) NewInt32Value(intVal int32, strVal []byte) base.EncodingValue {
	return &intValue{size: 4, intValue: int64(intVal), strValue: strVal}
}

// NewInt64Value creates a value that encodes as int64
func (*mysqlValueFactory) NewInt64Value(intVal int64, strVal []byte) base.EncodingValue {
	return &intValue{size: 8, intValue: intVal, strValue: strVal}
}
