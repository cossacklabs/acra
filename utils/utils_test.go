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
package utils_test

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"

	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
)

func TestFileExists(t *testing.T) {
	testPath := "/tmp/testfilepath"
	exists, err := utils.FileExists(testPath)
	if exists || err != nil {
		t.Fatalf("File exists or returned any error. err = %v\n", err)
	}
	_, err = os.Create(testPath)
	defer os.Remove(testPath)
	if err != nil {
		t.Fatalf("can't create test temporary file %v. err - %v\n", testPath, err)
	}
	exists, err = utils.FileExists(testPath)
	if !exists || err != nil {
		t.Fatalf("File not exists or returned any error. err = %v\n", err)
	}
}

func TestZeroizeSymmetricKey(t *testing.T) {
	symKey := make([]byte, 32)
	allZeros := make([]byte, 32)
	rand.Read(symKey)

	utils.ZeroizeSymmetricKey(symKey)

	if !bytes.Equal(symKey, allZeros) {
		t.Error("symmetrick key not zeroized")
	}
}

func TestZeroizeNilSymmetricKey(t *testing.T) {
	utils.ZeroizeSymmetricKey(nil) // no panic
}

func TestZeroizePrivateKey(t *testing.T) {
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatalf("failed to generated key pair: %v", err)
	}
	allZeros := make([]byte, len(keypair.Private.Value))

	utils.ZeroizePrivateKey(keypair.Private)

	if !bytes.Equal(keypair.Private.Value, allZeros) {
		t.Error("private key not zeroized")
	}
}

func TestZeroizeNilPrivateKey(t *testing.T) {
	utils.ZeroizePrivateKey(nil) // no panic
	utils.ZeroizePrivateKey(&keys.PrivateKey{})
}

func TestZeroizeKeyPair(t *testing.T) {
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatalf("failed to generated key pair: %v", err)
	}
	allZeros := make([]byte, len(keypair.Private.Value))
	oldPublicValue := make([]byte, len(keypair.Public.Value))
	copy(oldPublicValue, keypair.Public.Value)

	utils.ZeroizeKeyPair(keypair)

	if !bytes.Equal(keypair.Private.Value, allZeros) {
		t.Error("private key not zeroized")
	}
	if !bytes.Equal(keypair.Public.Value, oldPublicValue) {
		t.Error("public key has changed")
	}
}

func TestZeroizeNilKeyPair(t *testing.T) {
	utils.ZeroizeKeyPair(nil) // no panic
	utils.ZeroizeKeyPair(&keys.Keypair{})
}
