package postgresql

import (
	"context"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	"github.com/cossacklabs/acra/decryptor/postgresql/types"
	encryptor "github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
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
