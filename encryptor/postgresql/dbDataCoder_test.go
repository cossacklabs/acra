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
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	pg_query "github.com/Zhaars/pg_query_go/v4"

	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/utils"
)

func TestPostgresqlDBDataCoder_Decode(t *testing.T) {
	testData := []byte("some data")
	coder := &PostgresqlPgQueryDBDataCoder{}
	testCases := []*pg_query.A_Const{
		{
			Val: &pg_query.A_Const_Sval{
				Sval: &pg_query.String{
					Sval: fmt.Sprintf("%s", utils.EncodeToOctal(testData)),
				},
			},
		},
		{
			Val: &pg_query.A_Const_Sval{
				Sval: &pg_query.String{
					Sval: fmt.Sprintf("\\x%s", hex.EncodeToString(testData)),
				},
			},
		},
	}
	for _, expr := range testCases {
		data, err := coder.Decode(expr, &config.BasicColumnEncryptionSetting{})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, testData) {
			t.Fatalf("Expr: %s\nTook: %s\nExpected: %s", expr.String(), string(data), string(testData))
		}
	}
	errTestCases := []struct {
		Err  error
		Expr *pg_query.A_Const
	}{
		{
			Err: nil,
			// short data
			Expr: &pg_query.A_Const{
				Val: &pg_query.A_Const_Sval{
					Sval: &pg_query.String{
						Sval: string([]byte{1, 2, 3}),
					},
				},
			},
		},
		{
			Err: nil,
			// without prefix
			Expr: &pg_query.A_Const{
				Val: &pg_query.A_Const_Sval{
					Sval: &pg_query.String{
						Sval: fmt.Sprintf("%s", hex.EncodeToString(testData)),
					},
				},
			},
		},
		{
			Err: hex.ErrLength,
			// incorrect hex
			Expr: &pg_query.A_Const{
				Val: &pg_query.A_Const_Sval{
					Sval: &pg_query.String{
						Sval: fmt.Sprintf("\\x%s", hex.EncodeToString(testData)[1:]),
					},
				},
			},
		},

		{
			Err: nil,
			// without prefix
			Expr: &pg_query.A_Const{
				Val: &pg_query.A_Const_Sval{
					Sval: &pg_query.String{
						Sval: fmt.Sprintf("%s", hex.EncodeToString(testData)),
					},
				},
			},
		},

		{
			Err: hex.ErrLength,
			// incorrect hex
			Expr: &pg_query.A_Const{
				Val: &pg_query.A_Const_Sval{
					Sval: &pg_query.String{
						Sval: fmt.Sprintf("\\x%s", hex.EncodeToString(testData)[1:]),
					},
				},
			},
		},
	}
	for i, testCase := range errTestCases {
		_, err := coder.Decode(testCase.Expr, &config.BasicColumnEncryptionSetting{})
		if err != testCase.Err {
			t.Fatalf("[%d] Incorrect error. Took: %s; Expected: %s", i, err, testCase.Err.Error())
		}
	}
}

//
//func TestPostgresqlDBDataCoder_Encode(t *testing.T) {
//	testData := make([]byte, 100)
//	rand.Read(testData)
//	coder := &PostgresqlPgQueryDBDataCoder{}
//	testCases := []struct {
//		Expr   sqlparser.Expr
//		Output []byte
//	}{
//		{
//			Output: []byte(hex.EncodeToString(testData)),
//			Expr:   sqlparser.NewHexVal([]byte(hex.EncodeToString(testData))),
//		},
//		{
//			Output: []byte(fmt.Sprintf("\\x%s", hex.EncodeToString(testData))),
//			Expr:   sqlparser.NewStrVal(testData),
//		},
//		{
//			Output: utils.EncodeToOctal(testData),
//			Expr:   sqlparser.NewPgEscapeString(utils.EncodeToOctal(testData)),
//		},
//	}
//	for _, testCase := range testCases {
//		coded, err := coder.Encode(testCase.Expr, testData, &config.BasicColumnEncryptionSetting{})
//		if err != nil {
//			t.Fatal(err)
//		}
//		if !bytes.Equal(coded, testCase.Output) {
//			t.Fatalf("Expr: %s\nTook: %s\nExpected: %s", sqlparser.String(testCase.Expr), string(coded), string(testCase.Output))
//		}
//	}
//	if _, err := coder.Encode(sqlparser.NewFloatVal([]byte{1}), testData, &config.BasicColumnEncryptionSetting{}); err != base.ErrUnsupportedExpression {
//		t.Fatalf("Incorrect error. Took: %s; Expected: %s", err.Error(), base.ErrUnsupportedExpression.Error())
//	}
//}
