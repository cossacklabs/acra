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

package storage

import (
	"bytes"
	"testing"

	"github.com/cossacklabs/acra/pseudonymization/common"
)

type tokenKeyStore struct{}

func (t tokenKeyStore) GetClientIDSymmetricKeys(id []byte) ([][]byte, error) {
	return [][]byte{[]byte(`client key`)}, nil
}

func (t tokenKeyStore) GetClientIDSymmetricKey(id []byte) ([]byte, error) {
	return []byte(`client key`), nil
}

func (t tokenKeyStore) GetZoneIDSymmetricKeys(id []byte) ([][]byte, error) {
	return [][]byte{[]byte(`zone key`)}, nil
}

func (t tokenKeyStore) GetZoneIDSymmetricKey(id []byte) ([]byte, error) {
	return []byte(`zone key`), nil
}

func TestNewSCellEncryptor(t *testing.T) {
	encryptor, err := NewSCellEncryptor(tokenKeyStore{})
	if err != nil {
		t.Fatal(err)
	}
	type testcase struct {
		data    []byte
		context common.TokenContext
	}
	testData := []testcase{
		{[]byte(`some data`), common.TokenContext{}},
		{[]byte(`some data`), common.TokenContext{ClientID: []byte(`some context`)}},
		{[]byte(`some data`), common.TokenContext{ClientID: []byte(`some context`), ZoneID: []byte(`some context2`)}},
	}

	for _, tcase := range testData {
		encrypted, err := encryptor.Encrypt(tcase.data, tcase.context)
		if err != nil {
			t.Fatal(err)
		}
		decrypted, err := encryptor.Decrypt(encrypted, tcase.context)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decrypted, tcase.data) {
			t.Fatal("failed encrypt/decrypt operation")
		}
	}

}
