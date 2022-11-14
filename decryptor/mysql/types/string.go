package types

import (
	"context"
	"fmt"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	base_mysql "github.com/cossacklabs/acra/decryptor/mysql/base"
	"github.com/cossacklabs/acra/encryptor/config/common"
	log "github.com/sirupsen/logrus"
)

// StringDataTypeEncoder is encoder of TypeBlob in MySQL
type StringDataTypeEncoder struct{}

// Encode implementation of Encode method of DataTypeEncoder interface for byteaOID
func (t *StringDataTypeEncoder) Encode(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	if !base.IsDecryptedFromContext(ctx) {
		ctx, value, err := t.EncodeOnFail(ctx, format)
		if err != nil {
			return ctx, nil, err
		} else if value != nil {
			return ctx, value, nil
		}
		return ctx, nil, base_mysql.ErrConvertToDataType
	}

	return ctx, base_mysql.PutLengthEncodedString(data), nil
}

// Decode implementation of Decode method of DataTypeEncoder interface for byteaOID
func (t *StringDataTypeEncoder) Decode(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	return nil, nil, nil
}

// EncodeOnFail implementation of EncodeOnFail method of DataTypeEncoder interface for int4OID
func (t *StringDataTypeEncoder) EncodeOnFail(ctx context.Context, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
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
func (t *StringDataTypeEncoder) encodeDefault(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	return ctx, base_mysql.PutLengthEncodedString(data), nil
}

func init() {
	type_awareness.RegisterMySQLDataTypeIDEncoder(uint32(base_mysql.TypeString), &StringDataTypeEncoder{})
}
