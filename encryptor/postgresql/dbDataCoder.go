/*
Copyright 2018, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package postgresql

import (
	"encoding/hex"
	"strconv"
	"strings"

	pg_query "github.com/Zhaars/pg_query_go/v4"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
)

var pgHexStringPrefix = []byte{'\\', 'x'}

var hexNumPrefix = []byte{48, 120}

// PgEncodeToHexString encodes to hex with \x prefix
func PgEncodeToHexString(data []byte) []byte {
	newVal := make([]byte, len(pgHexStringPrefix)+hex.EncodedLen(len(data)))
	copy(newVal, pgHexStringPrefix)
	hex.Encode(newVal[len(pgHexStringPrefix):], data)
	return newVal
}

// PostgresqlPgQueryDBDataCoder responsible to handle decoding/encoding SQL literals before/after QueryEncryptor handlers
//
// Acra captures SQL queries like `INSERT INTO users (age, username, email, photo) VALUES (123, 'john_wick', 'johnwick@mail.com', '\xaabbcc');`
// and manipulates with SQL values `123`, `'john_wick'`, `'johnwick@mail.com'`, `'\xaabbcc'`. On first stage Acra
// decodes with Decode method values from SQL literals into binary or leave as is. For example hex encoded values decoded into binary"
// `'\xaabbcc'` decoded into []byte{170,187,204} and passed to QueryEncryptor's callbacks `EncryptWithClientID`
// After that it should be encoded with Encode method from binary form into SQL to replace values in the query.
type PostgresqlPgQueryDBDataCoder struct{}

// Decode hex/escaped literals to raw binary values for encryption/decryption. String values left as is because it
// doesn't need any decoding. Historically Int values had support only for tokenization and operated over string SQL
// literals.
func (*PostgresqlPgQueryDBDataCoder) Decode(aConst *pg_query.A_Const, setting config.ColumnEncryptionSetting) ([]byte, error) {
	if sval := aConst.GetSval(); sval != nil {
		if strings.HasPrefix(sval.GetSval(), "\\x") {
			// try to decode hex/octal encoding
			binValue, err := utils.DecodeEscaped([]byte(sval.GetSval()))
			if err != nil && err != utils.ErrDecodeOctalString {
				// return error on hex decode
				if _, ok := err.(hex.InvalidByteError); err == hex.ErrLength || ok {
					return nil, err
				} else if err == utils.ErrDecodeOctalString {
					return nil, err
				}

				logrus.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeSQLValue).Warningln("Can't decode value, process as unescaped string")
				// return value as is because it may be string with printable characters that wasn't encoded on client
				return []byte(sval.GetSval()), nil
			}
			return binValue, nil
		}

		// simple strings should be handled as is
		typeID := setting.GetDBDataTypeID()
		if typeID != 0 && typeID != pgtype.ByteaOID {
			return []byte(sval.GetSval()), nil
		}
		// bytea strings are escaped with \x hex value or with octal encoding

		// try to decode hex/octal encoding
		binValue, err := utils.DecodeEscaped([]byte(sval.GetSval()))
		if err != nil && err != utils.ErrDecodeOctalString {
			// return error on hex decode
			if _, ok := err.(hex.InvalidByteError); err == hex.ErrLength || ok {
				return nil, err
			} else if err == utils.ErrDecodeOctalString {
				return nil, err
			}

			logrus.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeSQLValue).Warningln("Can't decode value, process as unescaped string")
			// return value as is because it may be string with printable characters that wasn't encoded on client
			return []byte(sval.GetSval()), nil
		}
		return binValue, nil
	}

	if iVal := aConst.GetIval(); iVal != nil {
		val := int(aConst.GetIval().GetIval())
		return []byte(strconv.Itoa(val)), nil
	}

	if fVal := aConst.GetFval(); fVal != nil {
		return []byte(fVal.GetFval()), nil
	}

	return nil, base.ErrUnsupportedExpression
}

// Encode data to correct literal from binary data for this expression
func (*PostgresqlPgQueryDBDataCoder) Encode(aConst *pg_query.A_Const, data []byte, setting config.ColumnEncryptionSetting) error {
	switch {
	case aConst.GetFval() != nil:
		// if type is not byte array, then it probably string or int and we pass printable strings
		if setting.GetDBDataTypeID() != 0 && setting.GetDBDataTypeID() != pgtype.ByteaOID {
			// valid strings we pass as is without extra encoding
			if utils.IsPrintablePostgresqlString(data) {
				aConst.GetFval().Fval = string(data)
				return nil
			}
		}

		*aConst = pg_query.A_Const{
			Val: &pg_query.A_Const_Sval{
				Sval: &pg_query.String{
					Sval: "",
				},
			},
		}

		// valid string can contain escaped symbols, or tokenizer may generate string with symbols that should be escaped
		aConst.GetSval().Sval = string(PgEncodeToHexString(data))
		return nil
	case aConst.GetIval() != nil:
		if idata, err := strconv.ParseInt(string(data), 0, 32); err == nil {
			aConst.GetIval().Ival = int32(idata)
			return nil
		}

		if _, err := strconv.ParseInt(string(data), 0, 64); err == nil {
			*aConst = pg_query.A_Const{
				Val: &pg_query.A_Const_Fval{
					Fval: &pg_query.Float{
						Fval: string(data),
					},
				},
			}
			return nil
		}

		*aConst = pg_query.A_Const{
			Val: &pg_query.A_Const_Sval{
				Sval: &pg_query.String{
					Sval: "",
				},
			},
		}

		// else try to format it as string data
		// if type is not byte array, then it probably string or int and we pass printable strings
		if setting.GetDBDataTypeID() != 0 && setting.GetDBDataTypeID() != pgtype.ByteaOID {
			// valid strings we pass as is without extra encoding
			if utils.IsPrintablePostgresqlString(data) {
				aConst.GetSval().Sval = string(data)
				return nil
			}
		}
		// valid string can contain escaped symbols, or tokenizer may generate string with symbols that should be escaped
		aConst.GetSval().Sval = string(PgEncodeToHexString(data))
		return nil
	case aConst.GetSval() != nil:
		if setting.GetDBDataTypeID() != 0 && setting.GetDBDataTypeID() != pgtype.ByteaOID {
			// valid strings we pass as is without extra encoding
			if utils.IsPrintablePostgresqlString(data) {
				aConst.GetSval().Sval = string(data)
				return nil
			}
		}
		// byte array can be valid hex/octal encoded value, eventually we should encode it as binary data
		aConst.GetSval().Sval = string(PgEncodeToHexString(data))
		return nil
	}

	// if type is not byte array, then it probably string or int and we pass printable strings
	return base.ErrUnsupportedExpression
}
