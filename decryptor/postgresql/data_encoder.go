package postgresql

import (
	"context"
	"encoding/binary"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	"github.com/cossacklabs/acra/decryptor/postgresql/types"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
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

// OnColumn encode binary value to text and back. Should be before and after tokenizer processor
func (p *PgSQLDataEncoderProcessor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	if len(data) == 0 {
		return ctx, data, nil
	}

	columnSetting, ok := encryptor.EncryptionSettingFromContext(ctx)
	if !ok {
		// for case when data encrypted with acrastructs on app's side and used without any encryption setting
		columnSetting = &config.BasicColumnEncryptionSetting{}
	}
	logger := logging.GetLoggerFromContext(ctx).WithField("column", columnSetting.ColumnName()).WithField("decrypted", base.IsDecryptedFromContext(ctx))
	columnInfo, ok := base.ColumnInfoFromContext(ctx)
	if !ok {
		logger.WithField("processor", "PgSQLDataEncoderProcessor").Warningln("No column info in ctx")
		// we can't do anything
		return ctx, data, nil
	}

	dataTypesEncoders := type_awareness.GetPostgreSQLDataTypeIDEncoders()
	dataTypeIDEncoder, ok := dataTypesEncoders[columnSetting.GetDBDataTypeID()]
	if ok {
		return dataTypeIDEncoder.Encode(ctx, data, NewDataTypeFormat(columnInfo, columnSetting))
	}

	// here we process AcraStruct/AcraBlock decryption without any encryptor config that defines data_type/token_type
	// values. If it was decrypted then we return it as valid bytea value
	if base.IsDecryptedFromContext(ctx) {
		return types.NewByteaDataTypeEncoder().Encode(ctx, data, NewDataTypeFormat(columnInfo, columnSetting))
	}
	// If it wasn't decrypted (due to inappropriate keys or not AcraStructs as payload) then we return it in same way
	// as it come to us.
	encodedValue, ok := base.GetEncodedValueFromContext(ctx)
	if ok {
		return ctx, encodedValue, nil
	}
	return ctx, data, nil
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

	dataTypesEncoders := type_awareness.GetPostgreSQLDataTypeIDEncoders()
	dataTypeIDEncoder, ok := dataTypesEncoders[columnSetting.GetDBDataTypeID()]
	if ok {
		return dataTypeIDEncoder.Decode(ctx, data, NewDataTypeFormat(columnInfo, columnSetting))
	}

	if config.IsBinaryDataOperation(columnSetting) {
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
		return base.EncodedValueContext(ctx, data), decodedData, nil
	}
	// all other non-binary data should be valid SQL literals like integers or strings and Acra works with them as is
	return ctx, data, nil
}

// bytesValue is an EncodingValue that represents byte array
type bytesValue struct {
	bytes []byte
}

// AsBinary returns value encoded in postgres binary format
// For a byte sequence value this is an identity operation
func (v *bytesValue) AsBinary() []byte {
	return v.bytes
}

// AsText returns value encoded in postgres text format
// For a byte sequence value this is a hex encoded string
func (v *bytesValue) AsText() []byte {
	// all bytes should be encoded as valid bytea value
	return utils.PgEncodeToHex(v.bytes)
}

// intValue represents a {size*8}-bit integer ready for encoding
type intValue struct {
	size     int
	intValue int64
	strValue []byte
}

// AsBinary returns value encoded in postgres binary format
// For an int value it is a big endian encoded integer
func (v *intValue) AsBinary() []byte {
	newData := make([]byte, v.size)
	switch v.size {
	case 4:
		binary.BigEndian.PutUint32(newData, uint32(v.intValue))
	case 8:
		binary.BigEndian.PutUint64(newData, uint64(v.intValue))
	}
	return newData
}

// AsText returns value encoded in postgres text format
// For an int this means returning textual representation of the integer
func (v *intValue) AsText() []byte {
	return v.strValue
}

// stringValue is an EncodingValue that encodes data into string format
type stringValue struct {
	data []byte
}

// AsBinary returns value encoded in postgres binary format
// In other words, it returns data as it is
func (v *stringValue) AsBinary() []byte {
	return v.data
}

// AsText returns value encoded in postgres text format
// In other words, it returns data as it is
func (v *stringValue) AsText() []byte {
	return v.data
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
