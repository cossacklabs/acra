package types

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	"github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/jackc/pgx/pgtype"
	log "github.com/sirupsen/logrus"
)

// ByteaDataTypeEncoder is encoder of byteaOID type in PostgreSQL
type ByteaDataTypeEncoder struct{}

// NewByteaDataTypeEncoder create new ByteaDataTypeEncoder
func NewByteaDataTypeEncoder() *ByteaDataTypeEncoder {
	return &ByteaDataTypeEncoder{}
}

// Encode implementation of Encode method of DataTypeEncoder interface for byteaOID
func (t *ByteaDataTypeEncoder) Encode(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	if !base.IsDecryptedFromContext(ctx) {
		ctx, value, err := t.EncodeOnFail(ctx, format)
		if err != nil {
			return ctx, nil, err
		} else if value != nil {
			return ctx, value, nil
		}
	}

	if format.IsBinaryFormat() {
		return ctx, data, nil
	}
	return ctx, utils.PgEncodeToHex(data), nil
}

// Decode implementation of Decode method of DataTypeEncoder interface for byteaOID
func (t *ByteaDataTypeEncoder) Decode(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	if format.IsBinaryFormat() {
		return ctx, data, nil
	}

	if format.IsBinaryDataOperation() {
		// decryptor operates over blobs so all data types will be encrypted as hex/octal string values that we should
		// decode before decryption
		decodedData, err := utils.DecodeEscaped(data)
		if err != nil {
			if err == utils.ErrDecodeOctalString {
				return ctx, data, nil
			}
			log.WithError(err).Errorln("Can't decode binary data for decryption")
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

// EncodeOnFail implementation of EncodeOnFail method of DataTypeEncoder interface for int4OID
func (t *ByteaDataTypeEncoder) EncodeOnFail(ctx context.Context, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	action := format.GetResponseOnFail()
	switch action {
	case common.ResponseOnFailEmpty, common.ResponseOnFailCiphertext:
		return ctx, nil, nil

	case common.ResponseOnFailDefault:
		strValue := format.GetDefaultDataValue()
		if strValue == nil {
			log.Errorln("Default value is not specified")
			return ctx, nil, nil
		}
		return t.encodeDefault(ctx, []byte(*strValue), format)

	case common.ResponseOnFailError:
		return nil, nil, base.NewEncodingError(format.GetColumnName())
	}

	return ctx, nil, fmt.Errorf("unknown action: %q", action)
}

// EncodeDefault implementation of EncodeDefault method of DataTypeEncoder interface for byteaOID
func (t *ByteaDataTypeEncoder) encodeDefault(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	binValue, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		logging.GetLoggerFromContext(ctx).WithError(err).Errorln("Can't decode base64 default value")
		return ctx, nil, nil
	}
	if format.IsBinaryFormat() {
		return ctx, binValue, nil
	}
	return ctx, utils.PgEncodeToHex(binValue), nil
}

func init() {
	type_awareness.RegisterPostgreSQLDataTypeIDEncoder(pgtype.ByteaOID, &ByteaDataTypeEncoder{})
}
