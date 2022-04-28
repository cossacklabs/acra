package postgresql

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	common2 "github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
)

// PgSQLDataEncoderProcessor implements processor and encode binary/text values before sending to app
type PgSQLDataEncoderProcessor struct{}

// NewPgSQLDataEncoderProcessor return new data encoder to text/binary format
func NewPgSQLDataEncoderProcessor() (*PgSQLDataEncoderProcessor, error) {
	return &PgSQLDataEncoderProcessor{}, nil
}

// ID return name of processor
func (p *PgSQLDataEncoderProcessor) ID() string {
	return "PgSQLDataEncoderProcessor"
}

func (p *PgSQLDataEncoderProcessor) encodeToValue(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, encodingValue, error) {
	logger = logger.WithField("column", setting.ColumnName()).WithField("decrypted", base.IsDecryptedFromContext(ctx))
	if len(data) == 0 {
		return ctx, &identityValue{data}, nil
	}
	switch setting.GetEncryptedDataType() {
	case common2.EncryptedType_String:
		if !base.IsDecryptedFromContext(ctx) {
			value, err := encodeOnFail(setting, logger)
			if err != nil {
				return ctx, nil, err
			} else if value != nil {
				return ctx, value, nil
			}
		}
		// decrypted values return as is, without any encoding
		return ctx, &identityValue{data}, nil
	case common2.EncryptedType_Bytes:
		if !base.IsDecryptedFromContext(ctx) {
			value, err := encodeOnFail(setting, logger)
			if err != nil {
				return ctx, nil, err
			} else if value != nil {
				return ctx, value, nil
			}
		}
		return ctx, newByteSequence(data), nil
	case common2.EncryptedType_Int32, common2.EncryptedType_Int64:
		size := 8
		if setting.GetEncryptedDataType() == common2.EncryptedType_Int32 {
			size = 4
		}
		// convert back from text to binary
		strValue := string(data)
		// if it's valid string literal and decrypted, return as is
		value, err := strconv.ParseInt(strValue, 10, 64)
		if err == nil {
			val := intValue{size, value, strValue}
			return ctx, &val, nil
		}
		// if it's encrypted binary, then it is binary array that is invalid int literal
		if !base.IsDecryptedFromContext(ctx) {
			value, err := encodeOnFail(setting, logger)
			if err != nil {
				return ctx, nil, err
			} else if value != nil {
				return ctx, value, nil
			}
		}
		logger.Warningln("Can't decode int value and no default value")
		return ctx, &identityValue{data}, nil
	}
	// here we process AcraStruct/AcraBlock decryption without any encryptor config that defines data_type/token_type
	// values. If it was decrypted then we return it as valid bytea value
	if base.IsDecryptedFromContext(ctx) {
		return ctx, &byteSequenceValue{seq: data}, nil
	}
	// If it wasn't decrypted (due to inappropriate keys or not AcraStructs as payload) then we return it in same way
	// as it come to us.
	encodedValue, ok := getEncodedValueFromContext(ctx)
	if ok {
		return ctx, &identityValue{encodedValue}, nil
	}
	return ctx, &identityValue{data}, nil
}

// OnColumn encode binary value to text and back. Should be before and after tokenizer processor
func (p *PgSQLDataEncoderProcessor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	columnSetting, ok := encryptor.EncryptionSettingFromContext(ctx)
	if !ok {
		// for case when data encrypted with acrastructs on app's side and used without any encryption setting
		columnSetting = &config.BasicColumnEncryptionSetting{}
	}
	logger := logging.GetLoggerFromContext(ctx).WithField("column", columnSetting.ColumnName())
	columnInfo, ok := base.ColumnInfoFromContext(ctx)
	if !ok {
		logger.WithField("processor", "PgSQLDataEncoderProcessor").Warningln("No column info in ctx")
		// we can't do anything
		return ctx, data, nil
	}

	ctx, value, err := p.encodeToValue(ctx, data, columnSetting, columnInfo, logger)

	if err != nil || value == nil {
		return ctx, data, err
	}

	if columnInfo.IsBinaryFormat() {
		return ctx, value.asBinary(), nil
	}
	return ctx, value.asText(), nil
}

// PgSQLDataDecoderProcessor implements processor and decode binary/text values from DB
type PgSQLDataDecoderProcessor struct{}

// NewPgSQLDataDecoderProcessor return new data decoder from text/binary format from database side
func NewPgSQLDataDecoderProcessor() (*PgSQLDataDecoderProcessor, error) {
	return &PgSQLDataDecoderProcessor{}, nil
}

// ID return name of processor
func (p *PgSQLDataDecoderProcessor) ID() string {
	return "PgSQLDataDecoderProcessor"
}

func (p *PgSQLDataDecoderProcessor) decodeBinary(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	var newData [8]byte
	// convert from binary to text literal because tokenizer expects int value as string literal
	switch setting.GetEncryptedDataType() {
	case common2.EncryptedType_Int32, common2.EncryptedType_Int64:
		// We decode only tokenized data because it should be valid 4/8 byte values
		// If it is encrypted integers then we will see here encrypted blob that cannot be decoded and should be decrypted
		// in next handlers. So we return value as is

		// acra operates over string SQL values so here we expect valid int binary values that we should
		// convert to string SQL value
		if len(data) == 4 {
			// if high byte is 0xff then it is negative number and we should fill all previous bytes with 0xx too
			// otherwise with zeroes
			if data[0] == 0xff {
				copy(newData[:4], []byte{0xff, 0xff, 0xff, 0xff})
				copy(newData[4:], data)
			} else {
				// extend int32 from 4 bytes to int64 with zeroes
				copy(newData[:4], []byte{0, 0, 0, 0})
				copy(newData[4:], data)
			}
			// we accept here only 4 or 8 byte values
		} else if len(data) != 8 {
			return ctx, data, nil
		} else {
			copy(newData[:], data)
		}
		value := binary.BigEndian.Uint64(newData[:])
		return ctx, []byte(strconv.FormatInt(int64(value), 10)), nil
	}
	// binary and string values in binary format we return as is because it is encrypted blob
	return ctx, data, nil
}

// decodeText converts data from text format for decryptors/de-tokenizers according to ColumnEncryptionSetting
// hex/octal binary -> raw binary data
func (p *PgSQLDataDecoderProcessor) decodeText(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	if config.IsBinaryDataOperation(setting) {
		// decryptor operates over blobs so all data types will be encrypted as hex/octal string values that we should
		// decode before decryption
		decodedData, err := utils.DecodeEscaped(data)
		if err != nil {
			if err == utils.ErrDecodeOctalString {
				return ctx, data, nil
			}
			logger.WithError(err).Errorln("Can't decode binary data for decryption")
			return ctx, data, err
		}
		// save encoded value on successful decoding to return it as same value if decoded value wasn't need
		// or cannot be decrypted. Due to in some cases we cannot guess what type is it (if not matched any encryptor_config
		// setting) we should store it.
		return encodedValueContext(ctx, data), decodedData, nil
	}
	// all other non-binary data should be valid SQL literals like integers or strings and Acra works with them as is
	return ctx, data, nil
}

type decodedValueKey struct{}

// encodedValueContext save encoded value in the context. Can be used to save encoded value before decoding from database
// to return as is on decryption failures
func encodedValueContext(ctx context.Context, value []byte) context.Context {
	return context.WithValue(ctx, decodedValueKey{}, value)
}

// getEncodedValueFromContext returns encoded value and true if it was saved, otherwise returns nil, false
func getEncodedValueFromContext(ctx context.Context) ([]byte, bool) {
	value := ctx.Value(decodedValueKey{})
	if value == nil {
		return nil, false
	}
	val, ok := value.([]byte)
	if !ok {
		return nil, false
	}
	return val, true
}

// OnColumn encode binary value to text and back. Should be before and after tokenizer processor
func (p *PgSQLDataDecoderProcessor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	columnSetting, ok := encryptor.EncryptionSettingFromContext(ctx)
	if !ok {
		// for case when data encrypted with acrastructs on app's side and used without any encryption setting
		columnSetting = &config.BasicColumnEncryptionSetting{}
	}
	logger := logging.GetLoggerFromContext(ctx).WithField("column", columnSetting.ColumnName())
	columnInfo, ok := base.ColumnInfoFromContext(ctx)
	if !ok {
		logger.WithField("processor", "PgSQLDataDecoderProcessor").Warningln("No column info in ctx")
		// we can't do anything
		return ctx, data, nil
	}
	if columnInfo.IsBinaryFormat() {
		return p.decodeBinary(ctx, data, columnSetting, columnInfo, logger)
	}
	return p.decodeText(ctx, data, columnSetting, columnInfo, logger)
}

// encodingValue represents a (possibly parsed and prepared) value that is
// ready to be encoded
type encodingValue interface {
	asBinary() []byte
	asText() []byte
}

// byteSequenceValue is an abstraction over all byte-sequence values -- strings
// and []byte (because they are encoded in the same way)
type byteSequenceValue struct {
	seq []byte
}

func newByteSequence(seq []byte) encodingValue {
	return &byteSequenceValue{seq}
}

func (v byteSequenceValue) asBinary() []byte { return v.seq }
func (v byteSequenceValue) asText() []byte {
	// all bytes should be encoded as valid bytea value
	return utils.PgEncodeToHex(v.seq)
}

// intValue represents a {size*8}-bit integer ready for encoding
type intValue struct {
	size     int
	value    int64
	strValue string
}

func (v *intValue) asBinary() []byte {
	newData := make([]byte, v.size)
	switch v.size {
	case 4:
		binary.BigEndian.PutUint32(newData, uint32(v.value))
	case 8:
		binary.BigEndian.PutUint64(newData, uint64(v.value))
	}
	return newData
}

func (v *intValue) asText() []byte {
	return []byte(v.strValue)
}

// identityValue is an encodingValue that just returns data as is
type identityValue struct {
	data []byte
}

func (v *identityValue) asBinary() []byte { return v.data }
func (v *identityValue) asText() []byte   { return v.data }

// encodeDefault returns wrapped default value from settings ready for encoding
// returns nil if something went wrong, which in many cases indicates that the
// original value should be returned as it is
func encodeDefault(setting config.ColumnEncryptionSetting, logger *logrus.Entry) encodingValue {
	strValue := setting.GetDefaultDataValue()
	if strValue == nil {
		logger.Errorln("Default value is not specified")
		return nil
	}

	dataType := setting.GetEncryptedDataType()

	switch dataType {
	case common2.EncryptedType_String:
		return &identityValue{[]byte(*strValue)}
	case common2.EncryptedType_Bytes:
		binValue, err := base64.StdEncoding.DecodeString(*strValue)
		if err != nil {
			logger.WithError(err).Errorln("Can't decode base64 default value")
			return nil
		}
		return &byteSequenceValue{seq: binValue}
	case common2.EncryptedType_Int32, common2.EncryptedType_Int64:
		size := 8
		if dataType == common2.EncryptedType_Int32 {
			size = 4
		}
		value, err := strconv.ParseInt(*strValue, 10, 64)
		if err != nil {
			logger.WithError(err).Errorln("Can't parse default integer value")
			return nil
		}

		return &intValue{size: size, value: value, strValue: *strValue}
	}
	return nil
}

// encodeOnFail returns either an error, which should be returned, or value, which
// should be encoded, because there is some problem with original, or `nil`
// which indicates that original value should be returned as is.
func encodeOnFail(setting config.ColumnEncryptionSetting, logger *logrus.Entry) (encodingValue, error) {
	action := setting.GetResponseOnFail()
	switch action {
	case common2.ResponseOnFailEmpty, common2.ResponseOnFailCiphertext:
		return nil, nil

	case common2.ResponseOnFailDefault:
		return encodeDefault(setting, logger), nil

	case common2.ResponseOnFailError:
		return nil, base.NewEncodingError(setting.ColumnName())
	}

	return nil, fmt.Errorf("unknown action: %q", action)
}
