package postgresql

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	common2 "github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
	"strconv"
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

// here we process encryption/tokenization results before send it to a client
// acra decrypts or de-tokenize SQL literals, so we should convert string SQL literals to binary format
// if client expects int, then parse INT literals and convert to binary 4/8 byte format
// if expects bytes, then pass as is
// if expects string, then leave as is if it is valid string or encode to hex
// if it is encrypted data then we return default values or as is if applicable (binary data)
func (p *PgSQLDataEncoderProcessor) encodeBinary(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	if len(data) == 0 {
		return ctx, data, nil
	}
	switch setting.GetEncryptedDataType() {
	case common2.EncryptedType_String:
		if !base.IsDecryptedFromContext(ctx) {
			if newVal := setting.GetDefaultDataValue(); newVal != nil {
				return ctx, []byte(*newVal), nil
			}
		}
		return ctx, data, nil
	case common2.EncryptedType_Bytes:
		if !base.IsDecryptedFromContext(ctx) {
			if newVal := setting.GetDefaultDataValue(); newVal != nil {
				binValue, err := base64.StdEncoding.DecodeString(*newVal)
				if err == nil {
					return ctx, binValue, nil
				}
				logger.WithError(err).Errorln("Can't decode base64 default value")
			}
		}
		return ctx, data, nil
	case common2.EncryptedType_Int32, common2.EncryptedType_Int64:
		size := 8
		if setting.GetEncryptedDataType() == common2.EncryptedType_Int32 {
			size = 4
		}
		// convert back from text to binary
		value, err := strconv.ParseInt(string(data), 10, 64)
		// we don't return error to not cause connection drop on Acra side and pass it to app to deal with it
		if err != nil {
			if newVal := setting.GetDefaultDataValue(); newVal != nil {
				value, err = strconv.ParseInt(*newVal, 10, 64)
				if err != nil {
					logger.WithError(err).Errorln("Can't parse default integer value")
					return ctx, data, nil
				}
			} else {
				logger.WithError(err).Errorln("Can't decode int value and no default value")
				return ctx, data, nil
			}
		}
		newData := make([]byte, size)
		switch size {
		case 4:
			binary.BigEndian.PutUint32(newData, uint32(value))
		case 8:
			binary.BigEndian.PutUint64(newData, uint64(value))
		}
		return ctx, newData, nil
	}

	return ctx, data, nil
}

// encodeText converts data according to Text format received after decryption/de-tokenization according to ColumnEncryptionSetting
// binary -> hex encoded
// string/email -> string if valid UTF8/ASCII otherwise hex encoded
// integers as is
// not decrypted data that left in binary format we replace with default values (integers) or encode to hex (binary, strings)
func (p *PgSQLDataEncoderProcessor) encodeText(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	logger = logger.WithField("column", setting.ColumnName()).WithField("decrypted", base.IsDecryptedFromContext(ctx))
	logger.Debugln("Encode text")
	if len(data) == 0 {
		return ctx, data, nil
	}
	switch setting.GetEncryptedDataType() {
	case common2.EncryptedType_String:
		if !base.IsDecryptedFromContext(ctx) {
			if newVal := setting.GetDefaultDataValue(); newVal != nil {
				logger.WithField("default", *newVal).Debugln("Change with default")
				return ctx, []byte(*newVal), nil
			}
		}
	case common2.EncryptedType_Bytes:
		if !base.IsDecryptedFromContext(ctx) {
			if newVal := setting.GetDefaultDataValue(); newVal != nil {
				binValue, err := base64.StdEncoding.DecodeString(*newVal)
				if err != nil {
					return ctx, data, err
				}
				// override and encode at end of function
				data = binValue
			}
		}
	case common2.EncryptedType_Int32, common2.EncryptedType_Int64:
		_, err := strconv.ParseInt(string(data), 10, 64)
		// if it's valid string literal and decrypted, return as is
		if err == nil {
			return ctx, data, nil
		}
		// if it's encrypted binary, then it is binary array that is invalid int literal
		if !base.IsDecryptedFromContext(ctx) {
			if newVal := setting.GetDefaultDataValue(); newVal != nil {
				logger.Debugln("Return default value")
				return ctx, []byte(*newVal), nil
			}
		}
		logger.Warningln("Can't decode int value and no default value")
		return ctx, data, nil
	}
	if utils.IsPrintablePostgresqlString(data) {
		return ctx, data, nil
	}
	return ctx, utils.PgEncodeToHex(data), nil
}

// OnColumn encode binary value to text and back. Should be before and after tokenizer processor
func (p *PgSQLDataEncoderProcessor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
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
			logger.WithError(err).Errorln("Can't decode binary data for decryption")
			return ctx, data, nil
		}
		return ctx, decodedData, nil
	}
	// all other non-binary data should be valid SQL literals like integers or strings and Acra works with them as is
	return ctx, data, nil
}

// OnColumn encode binary value to text and back. Should be before and after tokenizer processor
func (p *PgSQLDataDecoderProcessor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	columnSetting, ok := encryptor.EncryptionSettingFromContext(ctx)
	if !ok {
		// for case when data encrypted with acrastructs on app's side and used without any encryption setting
		columnSetting = &config.BasicColumnEncryptionSetting{}
	}
	logger := logging.GetLoggerFromContext(ctx)
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
