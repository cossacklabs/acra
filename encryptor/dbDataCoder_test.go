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
	"fmt"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/utils"
	"testing"
)

func TestMysqlDBDataCoder_Decode(t *testing.T) {
	testData := []byte("some data")
	coder := &MysqlDBDataCoder{}
	testCases := []sqlparser.Expr{
		sqlparser.NewHexVal([]byte(hex.EncodeToString(testData))),
		sqlparser.NewStrVal(testData)}
	for _, expr := range testCases {
		data, err := coder.Decode(expr)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, testData) {
			t.Fatalf("Expr: %s\nTook: %s\nExpected: %s", sqlparser.String(expr), string(data), string(testData))
		}
	}

	errTestCases := []struct {
		Err  error
		Expr sqlparser.Expr
	}{
		{
			Err: hex.ErrLength,
			// incorrect hex value with incorrect length
			Expr: sqlparser.NewHexVal([]byte(hex.EncodeToString(testData))[1:]),
		},
		{
			Err:  errUnsupportedExpression,
			Expr: sqlparser.NewIntVal([]byte{1}),
		},
	}
	for _, testCase := range errTestCases {
		_, err := coder.Decode(testCase.Expr)
		if err != testCase.Err {
			t.Fatalf("Incorrect error. Took: %s; Expected: %s", err.Error(), testCase.Err.Error())
		}
	}
}

func TestMysqlDBDataCoder_Encode(t *testing.T) {
	testData := []byte("some data")
	coder := &MysqlDBDataCoder{}
	testCases := []struct {
		Expr   sqlparser.Expr
		Output []byte
	}{
		{
			Output: []byte(hex.EncodeToString(testData)),
			Expr:   sqlparser.NewHexVal([]byte(hex.EncodeToString(testData))),
		},
		{
			Output: testData,
			Expr:   sqlparser.NewStrVal(testData),
		},
	}
	for _, testCase := range testCases {
		coded, err := coder.Encode(testCase.Expr, testData)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(coded, testCase.Output) {
			t.Fatalf("Expr: %s\nTook: %s\nExpected: %s", sqlparser.String(testCase.Expr), string(coded), string(testCase.Output))
		}
	}

	if _, err := coder.Encode(sqlparser.NewIntVal([]byte{1}), testData); err != errUnsupportedExpression {
		t.Fatalf("Incorrect error. Took: %s; Expected: %s", err.Error(), errUnsupportedExpression.Error())
	}
}

func TestPostgresqlDBDataCoder_Decode(t *testing.T) {
	testData := []byte("some data")
	coder := &PostgresqlDBDataCoder{}
	testCases := []sqlparser.Expr{
		sqlparser.NewHexVal([]byte(hex.EncodeToString(testData))),
		sqlparser.NewStrVal([]byte(fmt.Sprintf("\\x%s", hex.EncodeToString(testData)))),
		sqlparser.NewPgEscapeString([]byte(fmt.Sprintf("\\x%s", hex.EncodeToString(testData)))),
	}
	for _, expr := range testCases {
		data, err := coder.Decode(expr)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, testData) {
			t.Fatalf("Expr: %s\nTook: %s\nExpected: %s", sqlparser.String(expr), string(data), string(testData))
		}
	}
	errTestCases := []struct {
		Err  error
		Expr sqlparser.Expr
	}{
		{
			Err: hex.ErrLength,
			// incorrect hex value with incorrect length
			Expr: sqlparser.NewHexVal([]byte(hex.EncodeToString(testData))[1:]),
		},
		{
			Err: utils.ErrDecodeOctalString,
			// short data
			Expr: sqlparser.NewStrVal([]byte{1, 2, 3}),
		},
		{
			Err: nil,
			// without prefix
			Expr: sqlparser.NewStrVal([]byte(fmt.Sprintf("%s", hex.EncodeToString(testData)))),
		},
		{
			Err: hex.ErrLength,
			// incorrect hex
			Expr: sqlparser.NewStrVal([]byte(fmt.Sprintf("\\x%s", hex.EncodeToString(testData)[1:]))),
		},
		// PgEscapeVal same as for StrVal
		{
			Err: utils.ErrDecodeOctalString,
			// short data
			Expr: sqlparser.NewPgEscapeString([]byte{1, 2, 3}),
		},
		{
			Err: nil,
			// without prefix
			Expr: sqlparser.NewPgEscapeString([]byte(fmt.Sprintf("%s", hex.EncodeToString(testData)))),
		},
		{
			Err: hex.ErrLength,
			// incorrect hex
			Expr: sqlparser.NewPgEscapeString([]byte(fmt.Sprintf("\\x%s", hex.EncodeToString(testData)[1:]))),
		},
	}
	for i, testCase := range errTestCases {
		_, err := coder.Decode(testCase.Expr)
		if err != testCase.Err {
			t.Fatalf("[%d] Incorrect error. Took: %s; Expected: %s", i, err, testCase.Err.Error())
		}
	}
}

func TestPostgresqlDBDataCoder_Encode(t *testing.T) {
	testData := []byte("some data")
	coder := &PostgresqlDBDataCoder{}
	testCases := []struct {
		Expr   sqlparser.Expr
		Output []byte
	}{
		{
			Output: []byte(hex.EncodeToString(testData)),
			Expr:   sqlparser.NewHexVal([]byte(hex.EncodeToString(testData))),
		},
		{
			Output: []byte(fmt.Sprintf("\\x%s", hex.EncodeToString(testData))),
			Expr:   sqlparser.NewStrVal(testData),
		},
		{
			Output: []byte(fmt.Sprintf("\\x%s", hex.EncodeToString(testData))),
			Expr:   sqlparser.NewPgEscapeString(testData),
		},
	}
	for _, testCase := range testCases {
		coded, err := coder.Encode(testCase.Expr, testData)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(coded, testCase.Output) {
			t.Fatalf("Expr: %s\nTook: %s\nExpected: %s", sqlparser.String(testCase.Expr), string(coded), string(testCase.Output))
		}
	}
	if _, err := coder.Encode(sqlparser.NewIntVal([]byte{1}), testData); err != errUnsupportedExpression {
		t.Fatalf("Incorrect error. Took: %s; Expected: %s", err.Error(), errUnsupportedExpression.Error())
	}
}
