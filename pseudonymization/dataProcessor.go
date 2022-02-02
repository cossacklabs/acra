package pseudonymization

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
	"strconv"
	"unicode/utf8"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/pseudonymization/common"
)

// TokenProcessor implements processor which tokenize/detokenize data for acra-server used in decryptor module
type TokenProcessor struct {
	tokenizer *DataTokenizer
}

// NewTokenProcessor return new processor
func NewTokenProcessor(tokenizer *DataTokenizer) (*TokenProcessor, error) {
	return &TokenProcessor{tokenizer}, nil
}

// ID return name of processor
func (p *TokenProcessor) ID() string {
	return "TokenProcessor"
}

// OnColumn tokenize data if configured by encryptor config
func (p *TokenProcessor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	accessContext := base.AccessContextFromContext(ctx)
	columnSetting, ok := encryptor.EncryptionSettingFromContext(ctx)
	if ok && columnSetting.IsTokenized() {
		tokenContext := common.TokenContext{ClientID: accessContext.GetClientID(), ZoneID: accessContext.GetZoneID()}
		data, err := p.tokenizer.Detokenize(data, tokenContext, columnSetting)
		return ctx, data, err
	}
	return ctx, data, nil
}

// ErrInvalidDataEncoderMode unsupported DataEncoderMode value
var ErrInvalidDataEncoderMode = errors.New("unsupported DataEncoderMode value")

// ErrInvalidIntValueBinarySize unsupported DataEncoderMode value
var ErrInvalidIntValueBinarySize = errors.New("unsupported binary size of int value")

// DataEncoderMode mode of PgSQLDataEncoderProcessor
type DataEncoderMode int8

// Available modes of DataEncoderMode
const (
	DataEncoderModeEncode = iota
	DataEncoderModeDecode
)

// PgSQLDataEncoderProcessor implements processor and encode/decode binary intX values to text format which acceptable by Tokenizer
type PgSQLDataEncoderProcessor struct {
	mode DataEncoderMode
}

// NewPgSQLDataEncoderProcessor return new data encoder/decoder from/to binary format for tokenization
func NewPgSQLDataEncoderProcessor(mode DataEncoderMode) (*PgSQLDataEncoderProcessor, error) {
	switch mode {
	case DataEncoderModeDecode, DataEncoderModeEncode:
		return &PgSQLDataEncoderProcessor{mode}, nil
	}
	return nil, ErrInvalidDataEncoderMode
}

// ID return name of processor
func (p *PgSQLDataEncoderProcessor) ID() string {
	return "PgSQLDataEncoderProcessor"
}

func (p *PgSQLDataEncoderProcessor) encodeBinary(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	// here we process encryption/tokenization results before send it to client
	// acra decrypts or de-tokenize SQL literals, so we should convert string SQL literals to binary format
	// if client expects int, then parse INT literals and convert to binary 4/8 byte format
	// if expects bytes, then pass as is
	// if expects string, then leave as is if it is valid string or encode to hex
	switch setting.GetTokenType() {
	case common.TokenType_Int32, common.TokenType_Int64:
		// convert back from text to binary
		value, err := strconv.ParseInt(string(data), 10, 64)
		if err != nil {
			return ctx, data, err
		}
		size := 8
		if setting.GetTokenType() == common.TokenType_Int32 {
			size = 4
		}
		newData := make([]byte, size)
		switch size {
		case 4:
			binary.BigEndian.PutUint32(newData, uint32(value))
			break
		case 8:
			binary.BigEndian.PutUint64(newData, uint64(value))
			break
		default:
			logger.WithField("size", size).Warningln("Unsupported int value size")
			return ctx, data, ErrInvalidIntValueBinarySize
		}
		return ctx, newData, nil
	case common.TokenType_String, common.TokenType_Email:
		if utils.IsPrintableASCIIArray(data) {
			// return as is
			break
		}
		// if it's really binary data then encode it to hex string
		output := make([]byte, hex.EncodedLen(len(data)))
		hex.Encode(output, data)
		return ctx, output, nil
	}

	return ctx, data, nil
}

func (p *PgSQLDataEncoderProcessor) decodeBinary(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	var newData [8]byte
	// convert from binary to text literal because tokenizer expects int value as string literal
	switch setting.GetTokenType() {
	case common.TokenType_Int32, common.TokenType_Int64:
		if setting.IsTokenized() {
			// tokenizer operates over string SQL values so here we expect valid int binary values that we should
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
			} else if len(newData) != 8 {
				return ctx, data, ErrInvalidIntValueBinarySize
			}
			value := binary.BigEndian.Uint64(newData[:])
			return ctx, []byte(strconv.FormatInt(int64(value), 10)), nil
		}
	}
	// binary and string values in binary format we return as is because it is encrypted blob
	return ctx, data, nil
}

// encodeText converts data according to Text format received after decryption/de-tokenization according to ColumnEncryptionSetting
func (p *PgSQLDataEncoderProcessor) encodeText(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	switch setting.GetTokenType() {
	case common.TokenType_Bytes:
		if len(data) == 0 {
			return ctx, data, nil
		}
		return ctx, utils.PgEncodeToHex(data), nil
	case common.TokenType_String, common.TokenType_Email:
		// string valid values we try return as is without extra conversion to HEX literals, otherwise encode them
		// to HEX
		if utils.IsPrintableASCIIArray(data) {
			return ctx, data, nil
		}
		if len(data) > 0 && utf8.Valid(data) {
			return ctx, data, nil
		}
		return ctx, utils.PgEncodeToHex(data), nil
	default:
		// integers and all other values return as is
		break
	}
	return ctx, data, nil
}

// decodeText converts data from text format for decryptors/de-tokenizers according to ColumnEncryptionSetting
func (p *PgSQLDataEncoderProcessor) decodeText(ctx context.Context, data []byte, setting config.ColumnEncryptionSetting, columnInfo base.ColumnInfo, logger *logrus.Entry) (context.Context, []byte, error) {
	if setting.OnlyEncryption() || setting.IsSearchable() {
		// decryptor operates over blobs so all data types will be encrypted as hex/octal string values that we should
		// decode before decryption
		decodedData, err := utils.DecodeEscaped(data)
		if err != nil {
			logger.WithError(err).Errorln("Can't decode binary data for decryption")
			return ctx, data, nil
		}
		return ctx, decodedData.Data(), nil
	}
	if setting.IsTokenized() {
		if setting.GetTokenType() == common.TokenType_Bytes {
			decodedData, err := utils.DecodeEscaped(data)
			if err != nil {
				logger.WithError(err).Errorln("Can't decode binary data for detokenization")
				return ctx, data, nil
			}
			return ctx, decodedData.Data(), nil
		}
		return ctx, data, nil
	}
	return ctx, data, nil
}

// OnColumn encode binary value to text and back. Should be before and after tokenizer processor
func (p *PgSQLDataEncoderProcessor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	columnSetting, ok := encryptor.EncryptionSettingFromContext(ctx)
	if !ok {
		return ctx, data, nil
	}
	logger := logging.GetLoggerFromContext(ctx)
	columnInfo, ok := base.ColumnInfoFromContext(ctx)
	if !ok {
		logger.WithField("processor", "PgSQLDataEncoderProcessor").Warningln("No column info in ctx")
		// we can't do anything
		return ctx, data, nil
	}

	if p.mode == DataEncoderModeEncode {
		if columnInfo.IsBinaryFormat() {
			return p.encodeBinary(ctx, data, columnSetting, columnInfo, logger)
		}
		return p.encodeText(ctx, data, columnSetting, columnInfo, logger)
	} else if p.mode == DataEncoderModeDecode {
		if columnInfo.IsBinaryFormat() {
			return p.decodeBinary(ctx, data, columnSetting, columnInfo, logger)
		}
		return p.decodeText(ctx, data, columnSetting, columnInfo, logger)
	} else {
		return ctx, data, ErrInvalidDataEncoderMode
	}
}
