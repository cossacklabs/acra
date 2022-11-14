package types

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	decryptor_mysql "github.com/cossacklabs/acra/decryptor/mysql"
	"github.com/cossacklabs/acra/decryptor/mysql/types/mysql"
	"github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

// LongLongDataTypeEncoder is encoder of TypeBlob in MySQL
type LongLongDataTypeEncoder struct{}

// Encode implementation of Encode method of DataTypeEncoder interface for byteaOID
func (t *LongLongDataTypeEncoder) Encode(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	strValue := utils.BytesToString(data)
	intValue, err := strconv.ParseInt(strValue, 10, 64)
	// if it's valid string literal and decrypted, return as is
	if err == nil {
		if format.IsBinaryFormat() {
			newData := make([]byte, 8)
			binary.LittleEndian.PutUint64(newData, uint64(intValue))
			return ctx, newData, nil
		}
		return ctx, decryptor_mysql.PutLengthEncodedString(data), nil
	}
	// if it's encrypted binary, then it is binary array that is invalid int literal
	if !base.IsDecryptedFromContext(ctx) {
		ctx, value, err := t.EncodeOnFail(ctx, format)
		if err != nil {
			return ctx, nil, err
		} else if value != nil {
			return ctx, value, nil
		}
		return ctx, nil, decryptor_mysql.ErrConvertToDataType
	}

	return ctx, nil, nil
}

// Decode implementation of Decode method of DataTypeEncoder interface for byteaOID
func (t *LongLongDataTypeEncoder) Decode(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	return nil, nil, nil
}

// EncodeOnFail implementation of EncodeOnFail method of DataTypeEncoder interface for int4OID
func (t *LongLongDataTypeEncoder) EncodeOnFail(ctx context.Context, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
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
func (t *LongLongDataTypeEncoder) encodeDefault(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	value, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		log.WithError(err).Errorln("Can't parse default integer value")
		return ctx, nil, err
	}

	if format.IsBinaryFormat() {
		newData := make([]byte, 8)
		binary.LittleEndian.PutUint64(newData, uint64(value))
		return ctx, newData, nil
	}
	return ctx, decryptor_mysql.PutLengthEncodedString(data), nil
}

func init() {
	type_awareness.RegisterMySQLDataTypeIDEncoder(uint32(mysql.TypeLongLong), &LongLongDataTypeEncoder{})
}
