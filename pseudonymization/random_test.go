/*
 * Copyright 2020, Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package pseudonymization

import (
	"regexp"
	"testing"
)

func TestEmailGeneration(t *testing.T) {
	checkEmail := func(email string) {
		bytes := []byte(email)
		randomEmail(bytes)
		// I know that this is not RFC 5322, but this is what our generator should output.
		stillEmail, err := regexp.Match("[[:alnum:]]+@[[:alnum:]]+\\.[[:alpha:]]+", bytes)
		if err != nil {
			t.Fatal(err)
		}
		if !stillEmail {
			t.Errorf("broken email: %s => %s", email, string(bytes))
		}
	}
	checkEmail("test@example.com")
	checkEmail("vassily.poupkine@bigco.has.long.address.net")
	checkEmail("m@i.ni")
}
