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

package encryptor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/utils"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/sirupsen/logrus"
	"strconv"
	"unicode/utf8"
)

var pgHexStringPrefix = []byte{'\\', 'x'}

var hexNumPrefix = []byte{48, 120}

// DBDataCoder encode/decode binary data to correct string form for specific db
type DBDataCoder interface {
	Decode(sqlparser.Expr, config.ColumnEncryptionSetting) ([]byte, error)
	Encode(sqlparser.Expr, []byte, config.ColumnEncryptionSetting) ([]byte, error)
}

// errUnsupportedExpression unsupported type of literal to binary encode/decode
var errUnsupportedExpression = errors.New("unsupported expression")

// MysqlDBDataCoder implement DBDataCoder for MySQL
type MysqlDBDataCoder struct{}

// Decode decode literals from string to byte slice
func (*MysqlDBDataCoder) Decode(expr sqlparser.Expr, _ config.ColumnEncryptionSetting) ([]byte, error) {
	switch val := expr.(type) {
	case *sqlparser.SQLVal:
		switch val.Type {
		case sqlparser.IntVal, sqlparser.StrVal:
			return val.Val, nil
		case sqlparser.HexVal:
			binValue := make([]byte, hex.DecodedLen(len(val.Val)))
			_, err := hex.Decode(binValue, val.Val)
			if err != nil {
				logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeHexData).WithError(err).Errorln("Can't decode hex string literal")
				return nil, err
			}
			return binValue, nil
		case sqlparser.HexNum:
			if !bytes.HasPrefix(val.Val, hexNumPrefix) {
				return val.Val, nil
			}
			binValue := make([]byte, hex.DecodedLen(len(val.Val)-2))
			_, err := hex.Decode(binValue, val.Val[2:])
			if err != nil {
				logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeHexData).WithError(err).Errorln("Can't decode hex binary literal")
				return nil, err
			}
			return binValue, nil
		}
	}
	return nil, errUnsupportedExpression
}

// Encode data to correct literal from binary data for this expression
func (*MysqlDBDataCoder) Encode(expr sqlparser.Expr, data []byte, _ config.ColumnEncryptionSetting) ([]byte, error) {
	encodeDataToHex := func(val *sqlparser.SQLVal, data []byte) ([]byte, error) {
		output := make([]byte, hex.EncodedLen(len(data)))
		hex.Encode(output, data)

		val.Type = sqlparser.HexVal
		return output, nil
	}

	switch val := expr.(type) {
	case *sqlparser.SQLVal:
		switch val.Type {
		case sqlparser.IntVal:
			// if data was just tokenized, so we return it as is because it is valid int literal
			if _, err := strconv.Atoi(utils.BytesToString(data)); err == nil {
				return data, nil
			}
			return encodeDataToHex(val, data)
		case sqlparser.StrVal:

			// if data is valid utf8 string so we return it as is
			if utf8.Valid(data) {
				return data, nil
			}
			return encodeDataToHex(val, data)
		case sqlparser.HexVal:
			return encodeDataToHex(val, data)
		case sqlparser.HexNum:
			hexData, err := encodeDataToHex(val, data)
			if err != nil {
				return nil, err
			}
			val.Type = sqlparser.HexNum

			//add Ox prefix before hexData
			hexNum := make([]byte, 0, len(hexData)+2)
			hexNum = append(hexNum, hexNumPrefix...)
			hexNum = append(hexNum, bytes.ToUpper(hexData)...)
			return hexNum, nil
		}
	}
	return nil, errUnsupportedExpression
}

// PgEncodeToHexString encodes to hex with \x prefix
func PgEncodeToHexString(data []byte) []byte {
	newVal := make([]byte, len(pgHexStringPrefix)+hex.EncodedLen(len(data)))
	copy(newVal, pgHexStringPrefix)
	hex.Encode(newVal[len(pgHexStringPrefix):], data)
	return newVal
}

// PostgresqlDBDataCoder responsible to handle decoding/encoding SQL literals before/after QueryEncryptor handlers
//
// Acra captures SQL queries like `INSERT INTO users (age, username, email, photo) VALUES (123, 'john_wick', 'johnwick@mail.com', '\xaabbcc');`
// and manipulates with SQL values `123`, `'john_wick'`, `'johnwick@mail.com'`, `'\xaabbcc'`. On first stage Acra
// decodes with Decode method values from SQL literals into binary or leave as is. For example hex encoded values decoded into binary"
// `'\xaabbcc'` decoded into []byte{170,187,204} and passed to QueryEncryptor's callbacks `EncryptWithClientID`
// After that it should be encoded with Encode method from binary form into SQL to replace values in the query.
type PostgresqlDBDataCoder struct{}

// Decode hex/escaped literals to raw binary values for encryption/decryption. String values left as is because it
// doesn't need any decoding. Historically Int values had support only for tokenization and operated over string SQL
// literals.
func (*PostgresqlDBDataCoder) Decode(expr sqlparser.Expr, setting config.ColumnEncryptionSetting) ([]byte, error) {
	switch val := expr.(type) {
	case *sqlparser.SQLVal:
		switch val.Type {
		case sqlparser.IntVal:
			return val.Val, nil
		case sqlparser.HexVal:
			binValue := make([]byte, hex.DecodedLen(len(val.Val)))
			_, err := hex.Decode(binValue, val.Val)
			if err != nil {
				logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeHexData).WithError(err).Errorln("Can't decode hex string literal")
				return nil, err
			}
			return binValue, err
		case sqlparser.PgEscapeString:
			// try to decode hex/octal encoding
			binValue, err := utils.DecodeEscaped(val.Val)
			if err != nil && err != utils.ErrDecodeOctalString {
				// return error on hex decode
				if _, ok := err.(hex.InvalidByteError); err == hex.ErrLength || ok {
					return nil, err
				} else if err == utils.ErrDecodeOctalString {
					return nil, err
				}

				logrus.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeSQLValue).Warningln("Can't decode value, process as unescaped string")
				// return value as is because it may be string with printable characters that wasn't encoded on client
				return val.Val, nil
			}
			return binValue, nil
		case sqlparser.StrVal:
			//// simple strings should be handled as is
			//typeID := setting.GetDBDataTypeID()
			//if typeID != 0 && typeID != pgtype.ByteaOID {
			//	return val.Val, nil
			//}
			// bytea strings are escaped with \x hex value or with octal encoding

			// try to decode hex/octal encoding
			binValue, err := utils.DecodeEscaped(val.Val)
			if err != nil && err != utils.ErrDecodeOctalString {
				// return error on hex decode
				if _, ok := err.(hex.InvalidByteError); err == hex.ErrLength || ok {
					return nil, err
				} else if err == utils.ErrDecodeOctalString {
					return nil, err
				}

				logrus.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeSQLValue).Warningln("Can't decode value, process as unescaped string")
				// return value as is because it may be string with printable characters that wasn't encoded on client
				return val.Val, nil
			}
			return binValue, nil
		}
	}
	return nil, errUnsupportedExpression
}

// Encode data to correct literal from binary data for this expression
func (*PostgresqlDBDataCoder) Encode(expr sqlparser.Expr, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	switch val := expr.(type) {
	case *sqlparser.SQLVal:
		switch val.Type {
		case sqlparser.HexVal:
			output := make([]byte, hex.EncodedLen(len(data)))
			hex.Encode(output, data)
			return output, nil
		case sqlparser.IntVal:
			// QueryDataEncryptor can tokenize INT SQL literal and we should not do anything because it is still valid
			// INT literal. Also, handler can encrypt data and replace SQL literal with encrypted data as []byte result.
			// Due to invalid format for INT literals, we should encode it as valid hex encoded binary value and change
			// type of SQL token for sqlparser that encoded into final SQL string

			// if data was just tokenized, so we return it as is because it is valid int literal
			if _, err := strconv.Atoi(string(data)); err == nil {
				return data, nil
			}
			// otherwise change type and pass it below for hex encoding
			val.Type = sqlparser.PgEscapeString
			fallthrough
		case sqlparser.PgEscapeString:
			// if type is not byte array, then it probably string or int and we pass printable strings
			if setting.GetDBDataTypeID() != 0 && setting.GetDBDataTypeID() != pgtype.ByteaOID {
				// valid strings we pass as is without extra encoding
				if utils.IsPrintablePostgresqlString(data) {
					return data, nil
				}
			}
			// valid string can contain escaped symbols, or tokenizer may generate string with symbols that should be escaped
			return utils.EncodeToOctal(data), nil
		case sqlparser.StrVal:
			// if type is not byte array, then it probably string or int and we pass printable strings
			if setting.GetDBDataTypeID() != 0 && setting.GetDBDataTypeID() != pgtype.ByteaOID {
				// valid strings we pass as is without extra encoding
				if utils.IsPrintablePostgresqlString(data) {
					return data, nil
				}
			}
			// byte array can be valid hex/octal encoded value, eventually we should encode it as binary data
			return PgEncodeToHexString(data), nil
		}
	}
	return nil, errUnsupportedExpression
}
