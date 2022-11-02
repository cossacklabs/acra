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

type Int4DataTypeEncoder struct{}

func (t *Int4DataTypeEncoder) Encode(ctx context.Context, data []byte, format type_awerness.DataTypeFormat) (context.Context, []byte, error) {
	// convert back from text to binary
	strValue := string(data)
	// if it's valid string literal and decrypted, return as is
	value, err := strconv.ParseInt(strValue, 10, 64)
	if err == nil {
		if format.IsBinaryFormat() {
			newData := make([]byte, 4)
			binary.BigEndian.PutUint32(newData, uint32(value))
			return ctx, newData, nil
		}
	}

	return ctx, data, nil
}

func (t *Int4DataTypeEncoder) Decode(ctx context.Context, data []byte, format type_awerness.DataTypeFormat) (context.Context, []byte, error) {
	if format.IsBinaryFormat() {
		var newData [8]byte
		// We decode only tokenized data because it should be valid 4/8 byte values
		// If it is encrypted integers then we will see here encrypted blob that cannot be decoded and should be decrypted
		// in next handlers. So we return value as is

		// acra operates over string SQL values so here we expect valid int binary values that we should
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
		} else if len(data) != 8 {
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

func (t *Int4DataTypeEncoder) EncodeDefault(ctx context.Context, data []byte, format type_awerness.DataTypeFormat) (context.Context, []byte, error) {
	value, err := strconv.ParseInt(string(data), 10, 32)
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
	type_awerness.RegisterPostgreSQLDataTypeIDEncoder(pgtype.Int4OID, &Int4DataTypeEncoder{})
}
