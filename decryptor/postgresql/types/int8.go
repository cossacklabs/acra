package types

import (
	"context"
	"encoding/binary"
	"strconv"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awerness"
	"github.com/cossacklabs/acra/utils"
	"github.com/jackc/pgx/pgtype"
	log "github.com/sirupsen/logrus"
)

type Int8DataTypeEncoder struct{}

func (t *Int8DataTypeEncoder) Encode(ctx context.Context, data []byte, format type_awerness.DataTypeFormat) (context.Context, []byte, error) {
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
	}

	return ctx, data, nil
}

func (t *Int8DataTypeEncoder) Decode(ctx context.Context, data []byte, format type_awerness.DataTypeFormat) (context.Context, []byte, error) {
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

func (t *Int8DataTypeEncoder) EncodeDefault(ctx context.Context, data []byte, format type_awerness.DataTypeFormat) (context.Context, []byte, error) {
	value, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		log.WithError(err).Errorln("Can't parse default integer value")
		return ctx, nil, err
	}

	if format.IsBinaryFormat() {
		newData := make([]byte, 4)
		binary.BigEndian.PutUint32(newData, uint32(value))
		return ctx, newData, nil
	}
	return ctx, data, nil
}

func init() {
	type_awerness.RegisterPostgreSQLDataTypeIDEncoder(pgtype.Int8OID, &Int8DataTypeEncoder{})
}
