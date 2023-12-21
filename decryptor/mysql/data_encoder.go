package mysql

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strconv"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	base_mysql "github.com/cossacklabs/acra/decryptor/mysql/base"
	"github.com/sirupsen/logrus"

	// explicitly import types package to force calls of init functions to register supported types
	_ "github.com/cossacklabs/acra/decryptor/mysql/types"
	encryptor "github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
)

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
		return ctx, base_mysql.PutLengthEncodedString(data), nil
	}

	var err error
	dataTypeIDEncoder, ok := type_awareness.GetMySQLDataTypeIDEncoders()[setting.GetDBDataTypeID()]
	if ok {

		var encoded []byte
		ctx, encoded, err = dataTypeIDEncoder.Encode(ctx, data, NewDataTypeFormat(columnInfo, setting))
		if err != nil && err != base_mysql.ErrConvertToDataType {
			return nil, nil, err
		}

		if encoded != nil {
			return ctx, encoded, nil
		}
	}

	var columnType = columnInfo.DataBinaryType()
	// in case of error on converting to defined type we should roll back field type and encode it as it was originally
	if err == base_mysql.ErrConvertToDataType {
		ctx = base.MarkErrorConvertedDataTypeContext(ctx)
		columnType = columnInfo.OriginBinaryType()
	}

	var encoded []byte
	// After processing, parse the value back and reencode it. Take care for the format to match.
	// The result must have exact same format as it had. Overflows are unacceptable.
	switch base_mysql.Type(columnType) {
	case base_mysql.TypeNull:
		if data != nil {
			return nil, nil, errors.New("NULL not kept NULL")
		}

	case base_mysql.TypeTiny:
		encoded = make([]byte, 1)
		intValue, err := strconv.ParseInt(utils.BytesToString(data), 10, 8)
		if err != nil {
			return nil, nil, err
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int8(intValue))
		return ctx, encoded, err

	case base_mysql.TypeShort, base_mysql.TypeYear:
		encoded = make([]byte, 2)
		intValue, err := strconv.ParseInt(utils.BytesToString(data), 10, 16)
		if err != nil {
			return nil, nil, err
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int16(intValue))
		return ctx, encoded, err

	case base_mysql.TypeInt24, base_mysql.TypeLong:
		encoded = make([]byte, 4)
		intValue, err := strconv.ParseInt(utils.BytesToString(data), 10, 32)
		if err != nil {
			return nil, nil, err
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int32(intValue))
		return ctx, encoded, err

	case base_mysql.TypeLongLong:
		encoded = make([]byte, 8)
		intValue, err := strconv.ParseInt(utils.BytesToString(data), 10, 64)
		if err != nil {
			return nil, nil, err
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int64(intValue))
		return ctx, encoded, err

	case base_mysql.TypeFloat:
		encoded = make([]byte, 4)
		floatValue, err := strconv.ParseFloat(utils.BytesToString(data), 32)
		if err != nil {
			return nil, nil, err
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, float32(floatValue))
		return ctx, encoded, err

	case base_mysql.TypeDouble:
		encoded = make([]byte, 8)
		floatValue, err := strconv.ParseFloat(utils.BytesToString(data), 64)
		if err != nil {
			return nil, nil, err
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, floatValue)
		return ctx, encoded, err
	}

	return ctx, base_mysql.PutLengthEncodedString(data), nil
}

func (p *BaseMySQLDataProcessor) encodeText(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	logger = logger.WithField("column", setting.ColumnName()).WithField("decrypted", base.IsDecryptedFromContext(ctx))
	logger.Debugln("Encode text")
	if len(data) == 0 {
		// we still need to encode result data as it might be null field in db
		return ctx, base_mysql.PutLengthEncodedString(data), nil
	}

	dataTypesEncoders := type_awareness.GetMySQLDataTypeIDEncoders()
	dataTypeIDEncoder, ok := dataTypesEncoders[setting.GetDBDataTypeID()]
	if !ok {
		return ctx, base_mysql.PutLengthEncodedString(data), nil
	}

	ctx, encoded, err := dataTypeIDEncoder.Encode(ctx, data, NewDataTypeFormat(columnInfo, setting))
	if err != nil && err != base_mysql.ErrConvertToDataType {
		return nil, nil, err
	}

	if encoded != nil {
		return ctx, encoded, nil
	}
	// in case of error on converting to defined type we should roll back field type and encode it as it was originally
	if err == base_mysql.ErrConvertToDataType {
		ctx = base.MarkErrorConvertedDataTypeContext(ctx)
	}

	return ctx, base_mysql.PutLengthEncodedString(data), nil
}

func (p *BaseMySQLDataProcessor) decodeBinary(ctx context.Context, encoded []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	// convert from binary to text literal because tokenizer expects int value as string literal
	columnType := columnInfo.DataBinaryType()
	if originType := columnInfo.OriginBinaryType(); originType != 0 {
		columnType = originType
	}

	switch base_mysql.Type(columnType) {
	case base_mysql.TypeNull:
		// do nothing

	case base_mysql.TypeTiny:
		var numericValue int8
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, strconv.AppendInt(nil, int64(numericValue), 10), nil

	case base_mysql.TypeShort, base_mysql.TypeYear:
		var numericValue int16
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, strconv.AppendInt(nil, int64(numericValue), 10), nil

	case base_mysql.TypeInt24, base_mysql.TypeLong:
		var numericValue int32
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, strconv.AppendInt(nil, int64(numericValue), 10), nil

	case base_mysql.TypeLongLong:
		var numericValue int64
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, strconv.AppendInt(nil, int64(numericValue), 10), nil

	case base_mysql.TypeFloat:
		var numericValue float32
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, strconv.AppendFloat(nil, float64(numericValue), 'G', -1, 32), nil

	case base_mysql.TypeDouble:
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

	dataTypesEncoders := type_awareness.GetMySQLDataTypeIDEncoders()
	dataTypeIDEncoder, ok := dataTypesEncoders[columnSetting.GetDBDataTypeID()]
	if ok {
		ctx, decoded, err := dataTypeIDEncoder.Decode(ctx, data, NewDataTypeFormat(columnInfo, columnSetting))
		if err != nil {
			return nil, nil, err
		}
		if decoded != nil {
			return ctx, decoded, nil
		}
	}

	if columnInfo.IsBinaryFormat() {
		return p.decodeBinary(ctx, data, columnSetting, columnInfo, logger)
	}
	return ctx, data, nil
}
