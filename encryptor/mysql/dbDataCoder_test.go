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
	"testing"

	"github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/sqlparser"
)

func TestMysqlDBDataCoder_Decode(t *testing.T) {
	coder := &MysqlDBDataCoder{}
	testCases := []struct {
		Input  sqlparser.Expr
		Output []byte
		Err    error
	}{
		{
			Input:  sqlparser.NewHexVal([]byte(hex.EncodeToString([]byte("test data")))),
			Output: []byte("test data"),
		},
		{
			Input:  sqlparser.NewStrVal([]byte("test data")),
			Output: []byte("test data"),
		},
		{
			Input:  sqlparser.NewIntVal([]byte("12345678")),
			Output: []byte("12345678"),
		},
		{
			Input: sqlparser.NewFloatVal([]byte("-2.71828")),
			Err:   base.ErrUnsupportedExpression,
		},
	}
	for _, testCase := range testCases {
		data, err := coder.Decode(testCase.Input, &config.BasicColumnEncryptionSetting{})
		if err != testCase.Err {
			t.Errorf("Expr: %s\nUnexpected error\nExpected: %v\nActual: %v", sqlparser.String(testCase.Input), testCase.Err, err)
			continue
		}
		if !bytes.Equal(data, testCase.Output) {
			t.Errorf("Expr: %s\nIncorrect output\nActual:   %s\nExpected: %s", sqlparser.String(testCase.Input), string(data), string(testCase.Output))
			continue
		}
	}
}

func TestMysqlDBDataCoder_Encode(t *testing.T) {
	coder := &MysqlDBDataCoder{}
	testCases := []struct {
		Expr   sqlparser.Expr
		Output []byte
		Input  []byte
		Err    error
	}{
		{
			Expr:   sqlparser.NewHexVal([]byte(hex.EncodeToString([]byte("some data")))),
			Input:  []byte("some data"),
			Output: []byte(hex.EncodeToString([]byte("some data"))),
		},
		{
			Expr:   sqlparser.NewStrVal([]byte("some data")),
			Input:  []byte("some data"),
			Output: []byte("some data"),
		},
		{
			Expr:   sqlparser.NewIntVal([]byte("1234")),
			Input:  []byte("1234"),
			Output: []byte("1234"),
		},
		{
			Expr:  sqlparser.NewFloatVal([]byte("3.1415")),
			Input: []byte("3.1415"),
			Err:   base.ErrUnsupportedExpression,
		},
	}
	for _, testCase := range testCases {
		coded, err := coder.Encode(testCase.Expr, testCase.Input, &config.BasicColumnEncryptionSetting{})
		if err != testCase.Err {
			t.Errorf("Expr: %s\nUnexpected error\nExpected: %v\nActual: %v", sqlparser.String(testCase.Expr), testCase.Err, err)
			continue
		}
		if !bytes.Equal(coded, testCase.Output) {
			t.Errorf("Expr: %s\nIncorrect output\nActual:   %s\nExpected: %s", sqlparser.String(testCase.Expr), string(coded), string(testCase.Output))
			continue
		}
	}
}
