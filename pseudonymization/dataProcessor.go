package pseudonymization

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/cossacklabs/acra/logging"
	"strconv"

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

// OnColumn encode binary value to text and back. Should be before and after tokenizer processor
func (p *PgSQLDataEncoderProcessor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	columnSetting, ok := encryptor.EncryptionSettingFromContext(ctx)
	if !(ok && columnSetting.IsTokenized()) {
		return ctx, data, nil
	}
	// process only int tokenization
	switch columnSetting.GetTokenType() {
	case common.TokenType_Int64, common.TokenType_Int32:
		break
	default:
		return ctx, data, nil
	}
	logger := logging.GetLoggerFromContext(ctx)
	newData := data
	columnInfo, ok := base.ColumnInfoFromContext(ctx)
	if !ok {
		logger.WithField("processor", "PgSQLDataEncoderProcessor").Warningln("No column info in ctx")
		// we can't do anything
		return ctx, data, nil
	}
	// we should decode only if data in binary format
	if !columnInfo.IsBinaryFormat() {
		return ctx, data, nil
	}
	if p.mode == DataEncoderModeEncode {
		// convert back from text to binary
		value, err := strconv.ParseInt(string(data), 10, 64)
		if err != nil {
			return ctx, data, err
		}
		newData = make([]byte, columnInfo.DataBinarySize())
		switch columnInfo.DataBinarySize() {
		case 4:
			binary.BigEndian.PutUint32(newData, uint32(value))
			break
		case 8:
			binary.BigEndian.PutUint64(newData, uint64(value))
			break
		default:
			logger.WithField("size", columnInfo.DataBinarySize()).Warningln("Unsupported int value size")
			return ctx, data, ErrInvalidIntValueBinarySize
		}
	} else if p.mode == DataEncoderModeDecode {
		// convert from binary to text literal because tokenizer expects int value as string literal
		switch columnSetting.GetTokenType() {
		case common.TokenType_Int32, common.TokenType_Int64:
			if len(newData) == 4 {
				// if high byte is 0xff then it is negative number and we should fill all previous bytes with 0xx too
				// otherwise with zeroes
				if data[0] == 0xff {
					newData = append([]byte{0xff, 0xff, 0xff, 0xff}, data...)
				} else {
					// extend int32 from 4 bytes to int64 with zeroes
					newData = append([]byte{0, 0, 0, 0}, data...)
				}
				// we accept here only 4 or 8 byte values
			} else if len(newData) != 8 {
				return ctx, data, ErrInvalidIntValueBinarySize
			}
			value := binary.BigEndian.Uint64(newData)
			newData = []byte(strconv.FormatInt(int64(value), 10))
		}
	} else {
		return ctx, data, ErrInvalidDataEncoderMode
	}
	return ctx, newData, nil

}
