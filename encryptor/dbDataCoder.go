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
	"encoding/hex"
	"errors"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
)

var pgHexStringPrefix = []byte{'\\', 'x'}

// DBDataCoder encode/decode binary data to correct string form for specific db
type DBDataCoder interface {
	Decode(sqlparser.Expr) ([]byte, error)
	Encode(sqlparser.Expr, []byte) ([]byte, error)
}

// errUnsupportedExpression unsupported type of literal to binary encode/decode
var errUnsupportedExpression = errors.New("unsupported expression")

// MysqlDBDataCoder implement DBDataCoder for MySQL
type MysqlDBDataCoder struct{}

// Decode decode literals from string to byte slice
func (*MysqlDBDataCoder) Decode(expr sqlparser.Expr) ([]byte, error) {
	switch val := expr.(type) {
	case *sqlparser.SQLVal:
		switch val.Type {
		case sqlparser.StrVal:
			return val.Val, nil
		case sqlparser.HexVal:
			binValue := make([]byte, hex.DecodedLen(len(val.Val)))
			_, err := hex.Decode(binValue, val.Val)
			if err != nil {
				logrus.WithError(err).Errorln("Can't decode hex string literal")
				return nil, err
			}
			return binValue, nil
		}
	}
	return nil, errUnsupportedExpression
}

// Encode data to correct literal from binary data for this expression
func (*MysqlDBDataCoder) Encode(expr sqlparser.Expr, data []byte) ([]byte, error) {
	switch val := expr.(type) {
	case *sqlparser.SQLVal:
		switch val.Type {
		case sqlparser.StrVal:
			return data, nil
		case sqlparser.HexVal:
			output := make([]byte, hex.EncodedLen(len(data)))
			hex.Encode(output, data)
			return output, nil
		}
	}
	return nil, errUnsupportedExpression
}

// PostgresqlDBDataCoder implement DBDataCoder for PostgreSQL
type PostgresqlDBDataCoder struct{}

// Decode literal in expression to binary
func (*PostgresqlDBDataCoder) Decode(expr sqlparser.Expr) ([]byte, error) {
	switch val := expr.(type) {
	case *sqlparser.SQLVal:
		switch val.Type {
		case sqlparser.HexVal:
			binValue := make([]byte, hex.DecodedLen(len(val.Val)))
			_, err := hex.Decode(binValue, val.Val)
			if err != nil {
				logrus.WithError(err).Errorln("Can't decode hex string literal")
				return nil, err
			}
			return binValue, err
		case sqlparser.PgEscapeString, sqlparser.StrVal:
			// try to decode hex/octal encoding
			binValue, err := utils.DecodeEscaped(val.Val)
			if err != nil {
				logrus.WithError(err).Warningln("Can't decode value, process as unescaped string")
				// return value as is because it may be string with printable characters that wasn't encoded on client
				return val.Val, nil
			}
			return binValue, nil
		}
	}
	return nil, errUnsupportedExpression
}

// Encode data to correct literal from binary data for this expression
func (*PostgresqlDBDataCoder) Encode(expr sqlparser.Expr, data []byte) ([]byte, error) {
	switch val := expr.(type) {
	case *sqlparser.SQLVal:
		switch val.Type {
		case sqlparser.HexVal:
			output := make([]byte, hex.EncodedLen(len(data)))
			hex.Encode(output, data)
			return output, nil
		case sqlparser.PgEscapeString, sqlparser.StrVal:
			newVal := make([]byte, len(pgHexStringPrefix)+hex.EncodedLen(len(data)))
			copy(newVal, pgHexStringPrefix)
			hex.Encode(newVal[len(pgHexStringPrefix):], data)
			return newVal, nil
		}
	}
	return nil, errUnsupportedExpression
}
