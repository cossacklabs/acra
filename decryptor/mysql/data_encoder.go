package mysql

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"github.com/cossacklabs/acra/encryptor/config/common"
	"strconv"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/sirupsen/logrus"
)

// BaseMySQLDataEncoderProcessor implements processor and encode/decode binary intX values to text format which acceptable by Tokenizer
type BaseMySQLDataEncoderProcessor struct{}

// EncodeMySQLDataEncoderProcessor implements processor and encode/decode binary intX values to text format which acceptable by Tokenizer
type EncodeMySQLDataEncoderProcessor struct {
	BaseMySQLDataEncoderProcessor
}

// NewEncodeMySQLDataEncoderProcessor return new data encoder from/to binary format for tokenization
func NewEncodeMySQLDataEncoderProcessor() *EncodeMySQLDataEncoderProcessor {
	return &EncodeMySQLDataEncoderProcessor{
		BaseMySQLDataEncoderProcessor{},
	}
}

// ID return name of processor
func (p *EncodeMySQLDataEncoderProcessor) ID() string {
	return "EncodeMySQLDataEncoderProcessor"
}

// DecodeMySQLDataEncoderProcessor implements processor and encode/decode binary intX values to text format which acceptable by Tokenizer
type DecodeMySQLDataEncoderProcessor struct {
	BaseMySQLDataEncoderProcessor
}

// NewDecodeMySQLDataEncoderProcessor return new data encoder from/to binary format for tokenization
func NewDecodeMySQLDataEncoderProcessor() *DecodeMySQLDataEncoderProcessor {
	return &DecodeMySQLDataEncoderProcessor{
		BaseMySQLDataEncoderProcessor{},
	}
}

// ID return name of processor
func (p *DecodeMySQLDataEncoderProcessor) ID() string {
	return "DecodeMySQLDataEncoderProcessor"
}

// here we process encryption/tokenization results before send it to a client
// acra decrypts or de-tokenize SQL literals, so we should convert string SQL literals to binary format
// if client expects int, then parse INT literals and convert to binary 4/8 byte format
// if expects bytes, then pass as is
// if expects string, then leave as is if it is valid string or encode to hex
// if it is encrypted data then we return default values or as is if applicable (binary data)
func (p *BaseMySQLDataEncoderProcessor) encodeBinary(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	logger = logger.WithField("column", setting.ColumnName()).WithField("decrypted", base.IsDecryptedFromContext(ctx))
	logger.Debugln("Encode binary")

	if len(data) == 0 {
		return ctx, data, nil
	}

	dataTypeEncoded, isEncoded, err := p.encodeWithDataType(ctx, data, setting)
	if err != nil {
		//todo: add error processing
		return nil, nil, err
	}

	if isEncoded {
		return ctx, dataTypeEncoded, nil
	}
	var encoded []byte
	var isNumericType bool
	// After processing, parse the value back and reencode it. Take care for the format to match.
	// The result must have exact same format as it had. Overflows are unacceptable.
	switch Type(columnInfo.DataBinaryType()) {
	case TypeNull:
		if data != nil {
			err = errors.New("NULL not kept NULL")
		}

	case TypeTiny:
		encoded = make([]byte, 1)
		intValue, err := strconv.ParseInt(string(data), 10, 8)
		if err != nil {
			break
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int8(intValue))
		isNumericType = true

	case TypeShort, TypeYear:
		encoded = make([]byte, 2)
		intValue, err := strconv.ParseInt(string(data), 10, 16)
		if err != nil {
			break
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int16(intValue))
		isNumericType = true

	case TypeInt24, TypeLong:
		encoded = make([]byte, 4)
		intValue, err := strconv.ParseInt(string(data), 10, 32)
		if err != nil {
			break
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int32(intValue))
		isNumericType = true

	case TypeLongLong:
		encoded = make([]byte, 8)
		intValue, err := strconv.ParseInt(string(data), 10, 64)
		if err != nil {
			break
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int64(intValue))
		isNumericType = true

	case TypeFloat:
		encoded = make([]byte, 4)
		floatValue, err := strconv.ParseFloat(string(data), 32)
		if err != nil {
			break
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, float32(floatValue))
		isNumericType = true

	case TypeDouble:
		encoded = make([]byte, 8)
		floatValue, err := strconv.ParseFloat(string(data), 64)
		if err != nil {
			break
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, float64(floatValue))
		isNumericType = true

	}
	if err != nil {
		//TODO: add error
		return ctx, data, nil
	}

	if isNumericType {
		return ctx, encoded, nil
	}

	return ctx, PutLengthEncodedString(data), nil
}

func (p *BaseMySQLDataEncoderProcessor) encodeWithDataType(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting) ([]byte, bool, error) {
	switch setting.GetEncryptedDataType() {
	case common.EncryptedType_Bytes:
		if !base.IsDecryptedFromContext(ctx) {
			if newValue := setting.GetDefaultDataValue(); newValue != nil {
				binValue, err := base64.StdEncoding.DecodeString(*newValue)
				if err != nil {
					return data, false, err
				}
				return PutLengthEncodedString(binValue), true, nil
			}
		}
		return data, false, nil
	case common.EncryptedType_String:
		if !base.IsDecryptedFromContext(ctx) {
			if value := setting.GetDefaultDataValue(); value != nil {
				return PutLengthEncodedString([]byte(*value)), true, nil
			}
		}
		return PutLengthEncodedString(data), true, nil
	case common.EncryptedType_Int32:
		encoded := make([]byte, 4)
		intValue, err := strconv.ParseInt(string(data), 10, 32)
		if err != nil {
			if newVal := setting.GetDefaultDataValue(); newVal != nil {
				intValue, err = strconv.ParseInt(*newVal, 10, 64)
				if err != nil {
					return data, false, err
				}
			}
			// TODO: ask Lagovas what to do in case of error casting to defined type.
			// Not sure we can return data as is as we already changed the field type and need rollback type as well.
			return data, false, err
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int32(intValue))
		return encoded, true, err

	case common.EncryptedType_Int64:
		encoded := make([]byte, 8)
		intValue, err := strconv.ParseInt(string(data), 10, 32)
		if err != nil {
			if newVal := setting.GetDefaultDataValue(); newVal != nil {
				intValue, err = strconv.ParseInt(*newVal, 10, 64)
				if err != nil {
					return data, false, err
				}
			}
			// TODO: ask Lagovas what to do in case of error casting to defined type.
			// Not sure we can return data as is as we already changed the field type and need rollback type as well.
			return data, false, err
		}
		err = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int32(intValue))
		return encoded, true, err
	}

	return data, false, nil
}

func (p *BaseMySQLDataEncoderProcessor) encodeText(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	logger = logger.WithField("column", setting.ColumnName()).WithField("decrypted", base.IsDecryptedFromContext(ctx))
	logger.Debugln("Encode text")
	if len(data) == 0 {
		return ctx, data, nil
	}

	switch setting.GetEncryptedDataType() {
	case common.EncryptedType_String:
		if !base.IsDecryptedFromContext(ctx) {
			if value := setting.GetDefaultDataValue(); value != nil {
				return ctx, PutLengthEncodedString([]byte(*value)), nil
			}
		}
	case common.EncryptedType_Bytes:
		if !base.IsDecryptedFromContext(ctx) {
			if newValue := setting.GetDefaultDataValue(); newValue != nil {
				binValue, err := base64.StdEncoding.DecodeString(*newValue)
				if err != nil {
					return ctx, nil, err
				}
				return ctx, PutLengthEncodedString(binValue), nil
			}
		}
	}
	return ctx, PutLengthEncodedString(data), nil
}

func (p *BaseMySQLDataEncoderProcessor) decodeBinary(ctx context.Context, encoded []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	// convert from binary to text literal because tokenizer expects int value as string literal
	switch Type(columnInfo.DataBinaryType()) {
	case TypeNull:
		// do nothing

	case TypeTiny:
		var numericValue int8
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, []byte(strconv.FormatInt(int64(numericValue), 10)), nil

	case TypeShort, TypeYear:
		var numericValue int16
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, []byte(strconv.FormatInt(int64(numericValue), 10)), nil

	case TypeInt24, TypeLong:
		var numericValue int32
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, []byte(strconv.FormatInt(int64(numericValue), 10)), nil

	case TypeLongLong:
		var numericValue int64
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, []byte(strconv.FormatInt(int64(numericValue), 10)), nil

	case TypeFloat:
		var numericValue float32
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, []byte(strconv.FormatFloat(float64(numericValue), 'G', -1, 32)), nil

	case TypeDouble:
		var numericValue float64
		err := binary.Read(bytes.NewReader(encoded), binary.LittleEndian, &numericValue)
		if err != nil {
			break
		}
		return ctx, []byte(strconv.FormatFloat(float64(numericValue), 'G', -1, 64)), nil
	}
	// binary and string values in binary format we return as is because it is encrypted blob
	return ctx, encoded, nil
}

// OnColumn encode binary value to text and back. Should be before and after tokenizer processor
func (p *EncodeMySQLDataEncoderProcessor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	columnSetting, ok := encryptor.EncryptionSettingFromContext(ctx)
	if !ok {
		// for case when data encrypted with acrastructs on app's side and used without any encryption setting
		columnSetting = &config.BasicColumnEncryptionSetting{}
	}
	logger := logging.GetLoggerFromContext(ctx)
	columnInfo, ok := base.ColumnInfoFromContext(ctx)
	if !ok {
		logger.WithField("processor", "PgSQLDataEncoderProcessor").Warningln("No column info in ctx")
		// we can't do anything
		return ctx, data, nil
	}
	if columnInfo.IsBinaryFormat() {
		return p.encodeBinary(ctx, data, columnSetting, columnInfo, logger)
	}
	return p.encodeText(ctx, data, columnSetting, columnInfo, logger)
}

// OnColumn encode binary value to text and back. Should be before and after tokenizer processor
func (p *DecodeMySQLDataEncoderProcessor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	columnSetting, ok := encryptor.EncryptionSettingFromContext(ctx)
	if !ok {
		// for case when data encrypted with acrastructs on app's side and used without any encryption setting
		columnSetting = &config.BasicColumnEncryptionSetting{}
	}
	logger := logging.GetLoggerFromContext(ctx)
	columnInfo, ok := base.ColumnInfoFromContext(ctx)
	if !ok {
		logger.WithField("processor", "PgSQLDataEncoderProcessor").Warningln("No column info in ctx")
		// we can't do anything
		return ctx, data, nil
	}

	if columnInfo.IsBinaryFormat() {
		return p.decodeBinary(ctx, data, columnSetting, columnInfo, logger)
	}
	return ctx, data, nil
}
