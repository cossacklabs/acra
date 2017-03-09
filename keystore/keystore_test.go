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

import "testing"

func TestValidateId(t *testing.T) {
	test_incorrect_input := []string{
		"qqqq!", // incorrect char at end
		"!qqqq", // incorrect char at start
		"qq@qq", // incorrect char in mid
		// short id
		"", "q", "qq", "qqq", "qqqq",
	}
	for _, input := range test_incorrect_input {
		if ValidateId([]byte(input)) {
			t.Errorf("Incorrect false validation. <%s> took", input)
		}
	}

	test_correct_input := []string{
		"qqqqq", "asdfzx", "фывап", "12345", "qwe12", "12qwe", "q1w2e",
		"      ", "________"}
	for _, input := range test_correct_input {
		if !ValidateId([]byte(input)) {
			t.Errorf("Incorrect true validation. <%s> took", input)
		}
	}
}
