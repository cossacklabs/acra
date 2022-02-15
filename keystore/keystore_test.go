/*
Copyright 2016, Cossack Labs Limited

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

package keystore

import (
	"bytes"
	"encoding/base64"
	"os"
	"testing"
)

func TestValidateID(t *testing.T) {
	testIncorrectInput := []string{
		"qqqq!",  // incorrect char at end
		"!qqqq",  // incorrect char at start
		"qq@qq",  // incorrect char in mid
		"фдлыво", // non ascii
		// short id
		"", "q", "qq", "qqq", "qqqq",
	}
	for _, input := range testIncorrectInput {
		if ValidateID([]byte(input)) {
			t.Errorf("Incorrect false validation. <%s> took", input)
		}
	}

	testCorrectInput := []string{
		"qqqqq", "asdfzx", "12345", "qwe12", "12qwe", "q1w2e",
		"      ", "________"}
	for _, input := range testCorrectInput {
		if !ValidateID([]byte(input)) {
			t.Errorf("Incorrect true validation. <%s> took", input)
		}
	}

	// check that return false for chars less than allowed
	for _, c := range []byte{'0', 'a', 'A'} {
		incorrectID := bytes.Repeat([]byte{c - 1}, MinClientIDLength)
		if ValidateID(incorrectID) {
			t.Errorf("Incorrect false validation. <%s> took", incorrectID)
		}
	}

	// check that return false for chars greater than allowed
	for _, c := range []byte{'9', 'z', 'Z'} {
		incorrectID := bytes.Repeat([]byte{c + 1}, MinClientIDLength)
		if ValidateID(incorrectID) {
			t.Errorf("Incorrect false validation. <%s> took", incorrectID)
		}
	}

	// check that can used lowest and highest chars
	for _, c := range []byte{'0', '9', 'a', 'A', 'z', 'Z'} {
		correctID := bytes.Repeat([]byte{c}, MinClientIDLength)
		if !ValidateID(correctID) {
			t.Errorf("Incorrect true validation. <%s> took", correctID)
		}
	}

	maxID := bytes.Repeat([]byte{'1'}, MaxClientIDLength)
	if !ValidateID(maxID) {
		t.Errorf("Incorrect true validation. <%s> took", maxID)
	}

	maxID = append(maxID, '1')
	if ValidateID(maxID) {
		t.Errorf("Incorrect false validation. <%s> took", maxID)
	}
}

func TestGetMasterKeyFromEnvironment(t *testing.T) {
	if err := os.Setenv(AcraMasterKeyVarName, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := GetMasterKeyFromEnvironment(); err != ErrEmptyMasterKey {
		t.Fatal("expected ErrEmptyMasterKey")
	}
	key := []byte("some key")
	if err := os.Setenv(AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}

	if _, err := GetMasterKeyFromEnvironment(); err != ErrMasterKeyIncorrectLength {
		t.Fatal("expected ErrMasterKeyIncorrectLength error")
	}

	key, err := GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv(AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}

	if envKey, err := GetMasterKeyFromEnvironment(); err != nil {
		t.Fatal(err)
	} else {
		if !bytes.Equal(envKey, key) {
			t.Fatal("keys not equal")
		}
	}
}

func TestGetEncryptionKey(t *testing.T) {
	// Ensure GetClientIDEncryptionKey returns 0th element of that GetClientIDSymmetricKeys returns

	// TODO

	// Ensure GetZoneIDEncryptionKey returns 0th element of that GetZoneIDSymmetricKeys returns

	// TODO
}