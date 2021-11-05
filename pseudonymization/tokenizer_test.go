/*
Copyright 2020, Cossack Labs Limited

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

package pseudonymization

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/cossacklabs/acra/pseudonymization/storage"
)

func TestPseudoanonymizer_Anonymize(t *testing.T) {
	type testcase struct {
		Value   interface{}
		Type    common.TokenType
		Context common.TokenContext
	}
	testcases := []testcase{
		{Value: "string", Type: common.TokenType_String, Context: common.TokenContext{}},
		{Value: "string", Type: common.TokenType_String, Context: common.TokenContext{ClientID: []byte(`some context`)}},
		{Value: "string", Type: common.TokenType_String, Context: common.TokenContext{ZoneID: []byte(`some context`)}},
		{Value: "string", Type: common.TokenType_String, Context: common.TokenContext{ClientID: []byte(`some context`), ZoneID: []byte(`some context`)}},
		{Value: []byte("bytes"), Type: common.TokenType_Bytes, Context: common.TokenContext{}},
		{Value: []byte("bytes"), Type: common.TokenType_Bytes, Context: common.TokenContext{ClientID: []byte(`some context2`)}},
		{Value: []byte("bytes"), Type: common.TokenType_Bytes, Context: common.TokenContext{ZoneID: []byte(`some context2`)}},
		{Value: []byte("bytes"), Type: common.TokenType_Bytes, Context: common.TokenContext{ClientID: []byte(`some context2`), ZoneID: []byte(`some context2`)}},
		{Value: int32(1), Type: common.TokenType_Int32, Context: common.TokenContext{}},
		{Value: int32(1), Type: common.TokenType_Int32, Context: common.TokenContext{ClientID: []byte(`some context3`)}},
		{Value: int32(1), Type: common.TokenType_Int32, Context: common.TokenContext{ZoneID: []byte(`some context3`)}},
		{Value: int32(1), Type: common.TokenType_Int32, Context: common.TokenContext{ClientID: []byte(`some context3`), ZoneID: []byte(`some context3`)}},
		{Value: int64(1), Type: common.TokenType_Int64, Context: common.TokenContext{}},
		{Value: int64(1), Type: common.TokenType_Int64, Context: common.TokenContext{ClientID: []byte(`some context4`)}},
		{Value: int64(1), Type: common.TokenType_Int64, Context: common.TokenContext{ZoneID: []byte(`some context4`)}},
		{Value: int64(1), Type: common.TokenType_Int64, Context: common.TokenContext{ClientID: []byte(`some context4`), ZoneID: []byte(`some context4`)}},
		{Value: common.Email("string"), Type: common.TokenType_Email, Context: common.TokenContext{}},
		{Value: common.Email("string"), Type: common.TokenType_Email, Context: common.TokenContext{ClientID: []byte(`some context5`)}},
		{Value: common.Email("string"), Type: common.TokenType_Email, Context: common.TokenContext{ZoneID: []byte(`some context5`)}},
		{Value: common.Email("string"), Type: common.TokenType_Email, Context: common.TokenContext{ClientID: []byte(`some context5`), ZoneID: []byte(`some context5`)}},
	}

	tokenStorage, err := storage.NewMemoryTokenStorage()
	if err != nil {
		t.Fatal(err)
	}

	tokenizer, err := NewPseudoanonymizer(tokenStorage)
	if err != nil {
		t.Fatal(err)
	}
	for _, tcase := range testcases {
		value, err := tokenizer.Anonymize(tcase.Value, tcase.Context, tcase.Type)
		if err != nil {
			t.Fatal(err)
		}
		sourceType := reflect.TypeOf(tcase.Value)
		newType := reflect.TypeOf(value)
		if sourceType != newType {
			t.Fatal("returned another type")
		}
		if reflect.DeepEqual(value, tcase.Value) {
			t.Fatal("expected new value, took the same")
		}

		// test with incorrect token type

		if _, err := tokenizer.Deanonymize(value, tcase.Context, incorrectTokenType(tcase.Type)); err != ErrDataTypeMismatch {
			t.Fatal(err)
		}

		sourceValue, err := tokenizer.Deanonymize(value, tcase.Context, tcase.Type)
		if err != nil {
			t.Fatal(err)
		}
		sourceType2 := reflect.TypeOf(sourceValue)
		if sourceType2 != sourceType {
			t.Fatal("returned another type after deanonymization")
		}
		if !reflect.DeepEqual(sourceValue, tcase.Value) {
			t.Fatal("returned another value after deanonymization")
		}
	}
}

func TestPseudoanonymizer_AnonymizeConsistently(t *testing.T) {
	type testcase struct {
		Value   interface{}
		Type    common.TokenType
		Context common.TokenContext
	}
	testcases := []testcase{
		{Value: "string", Type: common.TokenType_String, Context: common.TokenContext{}},
		{Value: "string", Type: common.TokenType_String, Context: common.TokenContext{ClientID: []byte(`some context`)}},
		{Value: "string", Type: common.TokenType_String, Context: common.TokenContext{ZoneID: []byte(`some context`)}},
		{Value: "string", Type: common.TokenType_String, Context: common.TokenContext{ClientID: []byte(`some context`), ZoneID: []byte(`some context`)}},

		{Value: []byte("bytes"), Type: common.TokenType_Bytes, Context: common.TokenContext{}},
		{Value: []byte("bytes"), Type: common.TokenType_Bytes, Context: common.TokenContext{ClientID: []byte(`some context2`)}},
		{Value: []byte("bytes"), Type: common.TokenType_Bytes, Context: common.TokenContext{ZoneID: []byte(`some context2`)}},
		{Value: []byte("bytes"), Type: common.TokenType_Bytes, Context: common.TokenContext{ClientID: []byte(`some context2`), ZoneID: []byte(`some context2`)}},

		{Value: int32(1), Type: common.TokenType_Int32, Context: common.TokenContext{}},
		{Value: int32(1), Type: common.TokenType_Int32, Context: common.TokenContext{ClientID: []byte(`some context3`)}},
		{Value: int32(1), Type: common.TokenType_Int32, Context: common.TokenContext{ZoneID: []byte(`some context3`)}},
		{Value: int32(1), Type: common.TokenType_Int32, Context: common.TokenContext{ClientID: []byte(`some context3`), ZoneID: []byte(`some context3`)}},

		{Value: int64(1), Type: common.TokenType_Int64, Context: common.TokenContext{}},
		{Value: int64(1), Type: common.TokenType_Int64, Context: common.TokenContext{ClientID: []byte(`some context4`)}},
		{Value: int64(1), Type: common.TokenType_Int64, Context: common.TokenContext{ZoneID: []byte(`some context4`)}},
		{Value: int64(1), Type: common.TokenType_Int64, Context: common.TokenContext{ClientID: []byte(`some context4`), ZoneID: []byte(`some context4`)}},

		{Value: common.Email("string"), Type: common.TokenType_Email, Context: common.TokenContext{}},
		{Value: common.Email("string"), Type: common.TokenType_Email, Context: common.TokenContext{ClientID: []byte(`some context5`)}},
		{Value: common.Email("string"), Type: common.TokenType_Email, Context: common.TokenContext{ZoneID: []byte(`some context5`)}},
		{Value: common.Email("string"), Type: common.TokenType_Email, Context: common.TokenContext{ClientID: []byte(`some context5`), ZoneID: []byte(`some context5`)}},
	}

	tokenStorage, err := storage.NewMemoryTokenStorage()
	if err != nil {
		t.Fatal(err)
	}

	tokenizer, err := NewPseudoanonymizer(tokenStorage)
	if err != nil {
		t.Fatal(err)
	}
	for _, tcase := range testcases {
		value1, err := tokenizer.AnonymizeConsistently(tcase.Value, tcase.Context, tcase.Type)
		if err != nil {
			t.Fatal(err)
		}
		sourceType := reflect.TypeOf(tcase.Value)
		newType := reflect.TypeOf(value1)
		if sourceType != newType {
			t.Fatal("returned another type")
		}
		if reflect.DeepEqual(value1, tcase.Value) {
			t.Fatal("expected new value, took same")
		}
		// anonymize one more time
		value2, err := tokenizer.AnonymizeConsistently(tcase.Value, tcase.Context, tcase.Type)
		if err != nil {
			t.Fatal(err)
		}
		sourceType = reflect.TypeOf(tcase.Value)
		newType = reflect.TypeOf(value2)
		if sourceType != newType {
			t.Fatal("returned another type")
		}
		if !reflect.DeepEqual(value1, value2) {
			t.Fatal("expected same value, took new")
		}

		// test with incorrect token type

		if _, err := tokenizer.Deanonymize(value1, tcase.Context, incorrectTokenType(tcase.Type)); err != ErrDataTypeMismatch {
			t.Fatal(err)
		}

		sourceValue, err := tokenizer.Deanonymize(value2, tcase.Context, tcase.Type)
		if err != nil {
			t.Fatal(err)
		}
		sourceType2 := reflect.TypeOf(sourceValue)
		if sourceType2 != sourceType {
			t.Fatal("returned another type after deanonymization")
		}
		if !reflect.DeepEqual(sourceValue, tcase.Value) {
			t.Fatal("returned another value after deanonymization")
		}
	}
}

// TestPseudoanonymizer_AnonymizeConsistentlySameValueDifferentContext check that same value with different context and same context with different values
// return different values
func TestPseudoanonymizer_AnonymizeConsistentlySameValueDifferentContext(t *testing.T) {
	type testcase struct {
		Value   interface{}
		Type    common.TokenType
		Context common.TokenContext
	}
	// set of values where same value and different context + same context and different values
	testcases := []testcase{
		{Value: "string", Type: common.TokenType_String, Context: common.TokenContext{}},
		{Value: "string1", Type: common.TokenType_String, Context: common.TokenContext{}},
		{Value: "string", Type: common.TokenType_String, Context: common.TokenContext{ClientID: []byte(`some context`)}},
		{Value: "string", Type: common.TokenType_String, Context: common.TokenContext{ClientID: []byte(`some context2`)}},
		{Value: "string", Type: common.TokenType_String, Context: common.TokenContext{ZoneID: []byte(`some context`)}},
		{Value: "string", Type: common.TokenType_String, Context: common.TokenContext{ZoneID: []byte(`some context2`)}},

		{Value: []byte("bytes"), Type: common.TokenType_Bytes, Context: common.TokenContext{}},
		{Value: []byte("bytes1"), Type: common.TokenType_Bytes, Context: common.TokenContext{}},
		{Value: []byte("bytes"), Type: common.TokenType_Bytes, Context: common.TokenContext{ClientID: []byte(`some context`)}},
		{Value: []byte("bytes"), Type: common.TokenType_Bytes, Context: common.TokenContext{ClientID: []byte(`some context2`)}},
		{Value: []byte("bytes"), Type: common.TokenType_Bytes, Context: common.TokenContext{ZoneID: []byte(`some context`)}},
		{Value: []byte("bytes"), Type: common.TokenType_Bytes, Context: common.TokenContext{ZoneID: []byte(`some context2`)}},

		{Value: int32(1), Type: common.TokenType_Int32, Context: common.TokenContext{}},
		{Value: int32(2), Type: common.TokenType_Int32, Context: common.TokenContext{}},
		{Value: int32(1), Type: common.TokenType_Int32, Context: common.TokenContext{ClientID: []byte(`some context`)}},
		{Value: int32(1), Type: common.TokenType_Int32, Context: common.TokenContext{ClientID: []byte(`some context2`)}},
		{Value: int32(1), Type: common.TokenType_Int32, Context: common.TokenContext{ZoneID: []byte(`some context`)}},
		{Value: int32(1), Type: common.TokenType_Int32, Context: common.TokenContext{ZoneID: []byte(`some context2`)}},

		{Value: int64(1), Type: common.TokenType_Int64, Context: common.TokenContext{}},
		{Value: int64(2), Type: common.TokenType_Int64, Context: common.TokenContext{}},
		{Value: int64(1), Type: common.TokenType_Int64, Context: common.TokenContext{ClientID: []byte(`some context`)}},
		{Value: int64(1), Type: common.TokenType_Int64, Context: common.TokenContext{ClientID: []byte(`some context2`)}},
		{Value: int64(1), Type: common.TokenType_Int64, Context: common.TokenContext{ZoneID: []byte(`some context`)}},
		{Value: int64(1), Type: common.TokenType_Int64, Context: common.TokenContext{ZoneID: []byte(`some context2`)}},

		{Value: common.Email("email@example.com"), Type: common.TokenType_Email, Context: common.TokenContext{}},
		{Value: common.Email("other@example.com"), Type: common.TokenType_Email, Context: common.TokenContext{}},
		{Value: common.Email("email@example.com"), Type: common.TokenType_Email, Context: common.TokenContext{ClientID: []byte(`some context`)}},
		{Value: common.Email("email@example.com"), Type: common.TokenType_Email, Context: common.TokenContext{ClientID: []byte(`some context2`)}},
		{Value: common.Email("email@example.com"), Type: common.TokenType_Email, Context: common.TokenContext{ZoneID: []byte(`some context`)}},
		{Value: common.Email("email@example.com"), Type: common.TokenType_Email, Context: common.TokenContext{ZoneID: []byte(`some context2`)}},
	}
	uniqueValues := make(map[string]struct{}, len(testcases))

	tokenStorage, err := storage.NewMemoryTokenStorage()
	if err != nil {
		t.Fatal(err)
	}

	tokenizer, err := NewPseudoanonymizer(tokenStorage)
	if err != nil {
		t.Fatal(err)
	}
	for _, tcase := range testcases {
		value, err := tokenizer.AnonymizeConsistently(tcase.Value, tcase.Context, tcase.Type)
		if err != nil {
			t.Fatal(err)
		}
		key, err := encodeToBytes(value, tcase.Type)
		if err != nil {
			t.Fatal(err)
		}
		previousLength := len(uniqueValues)
		uniqueValues[hex.EncodeToString(key)] = struct{}{}
		newLength := len(uniqueValues)
		if previousLength == newLength {
			t.Fatal("wasn't generated unique value")
		}

	}
}

func incorrectTokenType(token common.TokenType) common.TokenType {
	if token == common.TokenType_String {
		return common.TokenType_Email
	}
	return common.TokenType_String
}
