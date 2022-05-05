package postgresql

import (
	"context"
	"encoding/binary"
	"strconv"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	common2 "github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
)

var valueFactory base.EncodingValueFactory = &postgresValueFactory{}

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

func (p *PgSQLDataEncoderProcessor) encodeToValue(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, base.EncodingValue, error) {
	logger = logger.WithField("column", setting.ColumnName()).WithField("decrypted", base.IsDecryptedFromContext(ctx))
	if len(data) == 0 {
		return ctx, valueFactory.NewStringValue(data), nil
	}
	dataType := setting.GetEncryptedDataType()
	switch dataType {
	case common2.EncryptedType_String:
		if !base.IsDecryptedFromContext(ctx) {
			value, err := base.EncodeOnFail(setting, &postgresValueFactory{}, logger)
			if err != nil {
				return ctx, nil, err
			} else if value != nil {
				return ctx, value, nil
			}
		}
		// decrypted values return as is, without any encoding
		return ctx, valueFactory.NewStringValue(data), nil
	case common2.EncryptedType_Bytes:
		if !base.IsDecryptedFromContext(ctx) {
			value, err := base.EncodeOnFail(setting, &postgresValueFactory{}, logger)
			if err != nil {
				return ctx, nil, err
			} else if value != nil {
				return ctx, value, nil
			}
		}
		return ctx, valueFactory.NewBytesValue(data), nil
	case common2.EncryptedType_Int32, common2.EncryptedType_Int64:

		// convert back from text to binary
		strValue := string(data)
		// if it's valid string literal and decrypted, return as is
		value, err := strconv.ParseInt(strValue, 10, 64)
		if err == nil {
			if dataType == common2.EncryptedType_Int32 {
				return ctx, valueFactory.NewInt32Value(int32(value), data), nil
			}
			return ctx, valueFactory.NewInt64Value(value, data), nil
		}
		// if it's encrypted binary, then it is binary array that is invalid int literal
		if !base.IsDecryptedFromContext(ctx) {
			value, err := base.EncodeOnFail(setting, &postgresValueFactory{}, logger)
			if err != nil {
				return ctx, nil, err
			} else if value != nil {
				return ctx, value, nil
			}
		}
		logger.Warningln("Can't decode int value and no default value")
		return ctx, valueFactory.NewStringValue(data), nil
	}
	// here we process AcraStruct/AcraBlock decryption without any encryptor config that defines data_type/token_type
	// values. If it was decrypted then we return it as valid bytea value
	if base.IsDecryptedFromContext(ctx) {
		return ctx, valueFactory.NewBytesValue(data), nil
	}
	// If it wasn't decrypted (due to inappropriate keys or not AcraStructs as payload) then we return it in same way
	// as it come to us.
	encodedValue, ok := getEncodedValueFromContext(ctx)
	if ok {
		return ctx, valueFactory.NewStringValue(encodedValue), nil
	}
	return ctx, valueFactory.NewStringValue(data), nil
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
		return ctx, value.AsPostgresBinary(), nil
	}
	return ctx, value.AsPostgresText(), nil
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

// bytesValue is an EncodingValue that represents byte array
type bytesValue struct {
	bytes []byte
}

// AsPostgresBinary returns value encoded in postgres binary format
// For a byte sequence value this is an identity operation
func (v *bytesValue) AsPostgresBinary() []byte {
	return v.bytes
}

// AsPostgresText returns value encoded in postgres text format
// For a byte sequence value this is a hex encoded string
func (v *bytesValue) AsPostgresText() []byte {
	// all bytes should be encoded as valid bytea value
	return utils.PgEncodeToHex(v.bytes)
}

// AsMysqlBinary returns value encoded in mysql binary format
// For a byte sequence value this is the same as text encoding
func (v *bytesValue) AsMysqlBinary() []byte {
	panic("REMOVE THIS")
}

// AsMysqlText returns value encoded in mysql text format
// For a byte sequence value this is a length encoded string
func (v *bytesValue) AsMysqlText() []byte {
	panic("REMOVE THIS")
}

// intValue represents a {size*8}-bit integer ready for encoding
type intValue struct {
	size     int
	intValue int64
	strValue []byte
}

// AsPostgresBinary returns value encoded in postgres binary format
// For an int value it is a big endian encoded integer
func (v *intValue) AsPostgresBinary() []byte {
	newData := make([]byte, v.size)
	switch v.size {
	case 4:
		binary.BigEndian.PutUint32(newData, uint32(v.intValue))
	case 8:
		binary.BigEndian.PutUint64(newData, uint64(v.intValue))
	}
	return newData
}

// AsPostgresText returns value encoded in postgres text format
// For an int this means returning textual representation of the integer
func (v *intValue) AsPostgresText() []byte {
	return v.strValue
}

// AsMysqlBinary returns value encoded in mysql binary format
// For an int value it is a little endian encoded integer
func (v *intValue) AsMysqlBinary() []byte {
	panic("REMOVE THIS")
}

// AsMysqlText returns value encoded in mysql text format
// For an int this is a length encoded string of that integer
func (v *intValue) AsMysqlText() []byte {
	panic("REMOVE THIS")
}

// stringValue is an EncodingValue that encodes data into string format
type stringValue struct {
	data []byte
}

// AsPostgresBinary returns value encoded in postgres binary format
// In other words, it returns data as it is
func (v *stringValue) AsPostgresBinary() []byte {
	return v.data
}

// AsPostgresText returns value encoded in postgres text format
// In other words, it returns data as it is
func (v *stringValue) AsPostgresText() []byte {
	return v.data
}

// AsMysqlBinary returns value encoded in mysql binary format
// In other words, it encodes data into length encoded string
func (v *stringValue) AsMysqlBinary() []byte {
	panic("REMOVE THIS")
}

// AsMysqlText returns value encoded in mysql text format
// In other words, it encodes data into length encoded string
func (v *stringValue) AsMysqlText() []byte {
	panic("REMOVE THIS")
}

// postgresValueFactory is a factory that produces values that can encode into
// postgres format
type postgresValueFactory struct{}

// NewStringValue creates a value that encodes as a str
func (*postgresValueFactory) NewStringValue(str []byte) base.EncodingValue {
	return &stringValue{data: str}
}

// NewBytesValue creates a value that encodes as bytes
func (*postgresValueFactory) NewBytesValue(bytes []byte) base.EncodingValue {
	return &bytesValue{bytes}
}

// NewInt32Value creates a value that encodes as int32
func (*postgresValueFactory) NewInt32Value(intVal int32, strVal []byte) base.EncodingValue {
	return &intValue{size: 4, intValue: int64(intVal), strValue: strVal}
}

// NewInt64Value creates a value that encodes as int64
func (*postgresValueFactory) NewInt64Value(intVal int64, strVal []byte) base.EncodingValue {
	return &intValue{size: 8, intValue: intVal, strValue: strVal}
}
