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

package mysql

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"unicode/utf8"

	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/utils"
)

var hexNumPrefix = []byte{48, 120}

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
	return nil, base.ErrUnsupportedExpression
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
	return nil, base.ErrUnsupportedExpression
}
