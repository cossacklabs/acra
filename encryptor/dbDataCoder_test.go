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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/utils"
	"testing"
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
			Err:   errUnsupportedExpression,
		},
	}
	for _, testCase := range testCases {
		data, err := coder.Decode(testCase.Input)
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
			Err:   errUnsupportedExpression,
		},
	}
	for _, testCase := range testCases {
		coded, err := coder.Encode(testCase.Expr, testCase.Input)
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

func TestPostgresqlDBDataCoder_Decode(t *testing.T) {
	testData := []byte("some data")
	coder := &PostgresqlDBDataCoder{}
	testCases := []sqlparser.Expr{
		sqlparser.NewHexVal([]byte(hex.EncodeToString(testData))),
		sqlparser.NewPgEscapeString([]byte(fmt.Sprintf("%s", utils.EncodeToOctal(testData)))),
		sqlparser.NewStrVal([]byte(fmt.Sprintf("\\x%s", hex.EncodeToString(testData)))),
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
			Err: nil,
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
	testData := make([]byte, 100)
	rand.Read(testData)
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
	if _, err := coder.Encode(sqlparser.NewFloatVal([]byte{1}), testData); err != errUnsupportedExpression {
		t.Fatalf("Incorrect error. Took: %s; Expected: %s", err.Error(), errUnsupportedExpression.Error())
	}
}
