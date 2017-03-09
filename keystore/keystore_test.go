// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package keystore

import (
	"bytes"
	"testing"
)

func TestValidateId(t *testing.T) {
	test_incorrect_input := []string{
		"qqqq!",  // incorrect char at end
		"!qqqq",  // incorrect char at start
		"qq@qq",  // incorrect char in mid
		"фдлыво", // non ascii
		// short id
		"", "q", "qq", "qqq", "qqqq",
	}
	for _, input := range test_incorrect_input {
		if ValidateId([]byte(input)) {
			t.Errorf("Incorrect false validation. <%s> took", input)
		}
	}

	test_correct_input := []string{
		"qqqqq", "asdfzx", "12345", "qwe12", "12qwe", "q1w2e",
		"      ", "________"}
	for _, input := range test_correct_input {
		if !ValidateId([]byte(input)) {
			t.Errorf("Incorrect true validation. <%s> took", input)
		}
	}

	// check that return false for chars less than allowed
	for _, c := range []byte{'0', 'a', 'A'} {
		incorrect_id := bytes.Repeat([]byte{c - 1}, MIN_CLIENT_ID_LENGTH)
		if ValidateId(incorrect_id) {
			t.Errorf("Incorrect false validation. <%s> took", incorrect_id)
		}
	}

	// check that return false for chars greater than allowed
	for _, c := range []byte{'9', 'z', 'Z'} {
		incorrect_id := bytes.Repeat([]byte{c + 1}, MIN_CLIENT_ID_LENGTH)
		if ValidateId(incorrect_id) {
			t.Errorf("Incorrect false validation. <%s> took", incorrect_id)
		}
	}

	// check that can used lowest and highest chars
	for _, c := range []byte{'0', '9', 'a', 'A', 'z', 'Z'} {
		correct_id := bytes.Repeat([]byte{c}, MIN_CLIENT_ID_LENGTH)
		if !ValidateId(correct_id) {
			t.Errorf("Incorrect true validation. <%s> took", correct_id)
		}
	}

	max_id := bytes.Repeat([]byte{'1'}, MAX_CLIENT_ID_LENGTH)
	if !ValidateId(max_id) {
		t.Errorf("Incorrect true validation. <%s> took", max_id)
	}

	max_id = append(max_id, '1')
	if ValidateId(max_id) {
		t.Errorf("Incorrect false validation. <%s> took", max_id)
	}
}
