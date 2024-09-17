package types

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	base_mysql "github.com/cossacklabs/acra/decryptor/mysql/base"
	"github.com/cossacklabs/acra/encryptor/base/config/common"
	"github.com/cossacklabs/acra/utils"
)

// LongDataTypeEncoder is encoder of TypeLong in MySQL
type LongDataTypeEncoder struct{}

// Encode implementation of Encode method of DataTypeEncoder interface for TypeLong
func (t *LongDataTypeEncoder) Encode(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	strValue := utils.BytesToString(data)
	intValue, err := strconv.ParseInt(strValue, 10, 32)
	// if it's valid string literal and decrypted, return as is
	if err == nil {
		if format.IsBinaryFormat() {
			newData := make([]byte, 4)
			binary.LittleEndian.PutUint32(newData, uint32(intValue))
			return ctx, newData, nil
		}
		return ctx, base_mysql.PutLengthEncodedString(data), nil
	}
	// if it's encrypted binary, then it is binary array that is invalid int literal
	if !base.IsDecryptedFromContext(ctx) {
		ctx, value, err := t.EncodeOnFail(ctx, format)
		if err != nil {
			return ctx, nil, err
		} else if value != nil {
			return ctx, value, nil
		}
		return ctx, nil, base_mysql.ErrConvertToDataType
	}

	return ctx, nil, nil
}

// Decode implementation of Decode method of DataTypeEncoder interface for TypeLong
func (t *LongDataTypeEncoder) Decode(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	return nil, nil, nil
}

// EncodeOnFail implementation of EncodeOnFail method of DataTypeEncoder interface for TypeLong
func (t *LongDataTypeEncoder) EncodeOnFail(ctx context.Context, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
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

// EncodeDefault implementation of EncodeDefault method of DataTypeEncoder interface for TypeLong
func (t *LongDataTypeEncoder) encodeDefault(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	value, err := strconv.ParseInt(string(data), 10, 32)
	if err != nil {
		log.WithError(err).Errorln("Can't parse default integer value")
		return ctx, nil, err
	}

	if format.IsBinaryFormat() {
		newData := make([]byte, 4)
		binary.LittleEndian.PutUint32(newData, uint32(value))
		return ctx, newData, nil
	}
	return ctx, base_mysql.PutLengthEncodedString(data), nil
}

// ValidateDefaultValue implementation of ValidateDefaultValue method of DataTypeEncoder interface for TypeLong
func (t *LongDataTypeEncoder) ValidateDefaultValue(value *string) error {
	_, err := strconv.ParseInt(*value, 10, 32)
	return err
}

func init() {
	type_awareness.RegisterMySQLDataTypeIDEncoder(uint32(base_mysql.TypeLong), &LongDataTypeEncoder{})
}
