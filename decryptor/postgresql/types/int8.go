package types

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	"github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/cossacklabs/acra/utils"
	"github.com/jackc/pgx/pgtype"
	log "github.com/sirupsen/logrus"
)

// Int8DataTypeEncoder is encoder of int8OID type in PostgreSQL
type Int8DataTypeEncoder struct{}

// Encode implementation of Encode method of DataTypeEncoder interface for int8OID
func (t *Int8DataTypeEncoder) Encode(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	// convert back from text to binary
	strValue := string(data)
	// if it's valid string literal and decrypted, return as is
	value, err := strconv.ParseInt(strValue, 10, 64)
	if err == nil {
		if format.IsBinaryFormat() {
			newData := make([]byte, 8)
			binary.BigEndian.PutUint64(newData, uint64(value))
			return ctx, newData, nil
		}
		return ctx, data, nil
	}

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

// Decode implementation of Decode method of DataTypeEncoder interface for int8OID
func (t *Int8DataTypeEncoder) Decode(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	if format.IsBinaryFormat() {
		var newData [8]byte
		// We decode only tokenized data because it should be valid 4/8 byte values
		// If it is encrypted integers then we will see here encrypted blob that cannot be decoded and should be decrypted
		// in next handlers. So we return value as is
		if len(data) != 8 {
			return ctx, data, nil
		} else {
			copy(newData[:], data)
		}
		value := binary.BigEndian.Uint64(newData[:])
		return ctx, []byte(strconv.FormatInt(int64(value), 10)), nil
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
func (t *Int8DataTypeEncoder) EncodeOnFail(ctx context.Context, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
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

// encodeDefault implementation of EncodeDefault method of DataTypeEncoder interface for int8OID
func (t *Int8DataTypeEncoder) encodeDefault(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	value, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		log.WithError(err).Errorln("Can't parse default integer value")
		return ctx, nil, err
	}

	if format.IsBinaryFormat() {
		newData := make([]byte, 8)
		binary.BigEndian.PutUint64(newData, uint64(value))
		return ctx, newData, nil
	}
	return ctx, data, nil
}

func init() {
	type_awareness.RegisterPostgreSQLDataTypeIDEncoder(pgtype.Int8OID, &Int8DataTypeEncoder{})
}
