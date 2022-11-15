package types

import (
	"context"
	"fmt"
	"unicode/utf8"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	"github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/cossacklabs/acra/utils"
	"github.com/jackc/pgx/pgtype"
	log "github.com/sirupsen/logrus"
)

// TextDataType is encoder of textOID type in PostgreSQL
type TextDataType struct{}

// Encode implementation of Encode method of DataTypeEncoder interface for textOID
func (t *TextDataType) Encode(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	if !base.IsDecryptedFromContext(ctx) {
		ctx, value, err := t.EncodeOnFail(ctx, format)
		if err != nil {
			return ctx, nil, err
		} else if value != nil {
			return ctx, value, nil
		}
	}

	return ctx, data, nil
}

// Decode implementation of Decode method of DataTypeEncoder interface for textOID
func (t *TextDataType) Decode(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
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
func (t *TextDataType) EncodeOnFail(ctx context.Context, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
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
		return ctx, []byte(*strValue), nil

	case common.ResponseOnFailError:
		return nil, nil, base.NewEncodingError(format.GetColumnName())
	}

	return ctx, nil, fmt.Errorf("unknown action: %q", action)
}

// ValidateDefaultValue implementation of ValidateDefaultValue method of DataTypeEncoder interface for textOID
func (t *TextDataType) ValidateDefaultValue(value *string) error {
	if !utf8.ValidString(*value) {
		return fmt.Errorf("invalid utf8 string")
	}
	return nil
}

func init() {
	type_awareness.RegisterPostgreSQLDataTypeIDEncoder(pgtype.TextOID, &TextDataType{})
}
