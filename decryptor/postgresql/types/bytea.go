package types

import (
	"context"
	"encoding/base64"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awerness"
	"github.com/cossacklabs/acra/utils"
	"github.com/jackc/pgx/pgtype"
	log "github.com/sirupsen/logrus"
)

type ByteaDataTypeEncoder struct{}

func (t *ByteaDataTypeEncoder) Encode(ctx context.Context, data []byte, format type_awerness.DataTypeFormat) (context.Context, []byte, error) {
	if format.IsBinaryFormat() {
		return ctx, data, nil
	}
	return ctx, utils.PgEncodeToHex(data), nil
}

func (t *ByteaDataTypeEncoder) Decode(ctx context.Context, data []byte, format type_awerness.DataTypeFormat) (context.Context, []byte, error) {
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

func (t *ByteaDataTypeEncoder) EncodeDefault(ctx context.Context, data []byte, format type_awerness.DataTypeFormat) (context.Context, []byte, error) {
	binValue, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		log.WithError(err).Errorln("Can't decode base64 default value")
		return ctx, nil, err
	}
	return t.Encode(ctx, binValue, format)
}

func init() {
	type_awerness.RegisterPostgreSQLDataTypeIDEncoder(pgtype.ByteaOID, &ByteaDataTypeEncoder{})
}
