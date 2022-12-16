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

package keys

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cossacklabs/acra/keystore"
)

func TestPrintKeysDefault(t *testing.T) {
	keys := []keystore.KeyDescription{
		{
			ID:      "Another ID",
			Purpose: "testing",
		},
	}

	output := strings.Builder{}
	err := PrintKeys(keys, &output, &CommonKeyListingParameters{useJSON: false})
	if err != nil {
		t.Fatalf("Failed to print keys: %v", err)
	}

	actual := output.String()
	expected := `Key purpose | Client | Key ID
------------+--------+-----------
testing     |        | Another ID
`
	if actual != expected {
		t.Errorf("Incorrect output.\nActual:\n%s\nExpected:\n%s", actual, expected)
	}
}

func TestPrintKeysJSON(t *testing.T) {
	keys := []keystore.KeyDescription{
		{
			ID:      "Another ID",
			Purpose: "testing",
		},
	}

	output := bytes.Buffer{}
	err := PrintKeys(keys, &output, &CommonKeyListingParameters{useJSON: true})
	if err != nil {
		t.Fatalf("Failed to print keys: %v", err)
	}

	var actual []keystore.KeyDescription
	err = json.Unmarshal(output.Bytes(), &actual)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON output: %v", err)
	}

	if !equalDescriptionLists(actual, keys) {
		t.Errorf("Incorrect output:\n%s", string(output.Bytes()))
	}
}

func equalDescriptionLists(a, b []keystore.KeyDescription) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !equalDescriptions(a[i], b[i]) {
			return false
		}
	}
	return true
}

func equalDescriptions(a, b keystore.KeyDescription) bool {
	return a.ID == b.ID && a.Purpose == b.Purpose &&
		bytes.Equal(a.ClientID, b.ClientID)
}
