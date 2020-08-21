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
	"testing"

	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/themis/gothemis/keys"
)

type keyStore struct {
	keypair            *keys.Keypair
	zoneKeyTouched     bool
	clientIDKeyTouched bool
}

func (ks *keyStore) GetZonePublicKey(zoneID []byte) (*keys.PublicKey, error) {
	ks.zoneKeyTouched = true
	return ks.keypair.Public, nil
}

func (ks *keyStore) GetClientIDEncryptionPublicKey(clientID []byte) (*keys.PublicKey, error) {
	ks.clientIDKeyTouched = true
	return ks.keypair.Public, nil
}

type emptyEncryptionSetting struct{}

func (*emptyEncryptionSetting) ColumnName() string {
	panic("implement me")
}

func (*emptyEncryptionSetting) ClientID() []byte {
	panic("implement me")
}

func (*emptyEncryptionSetting) ZoneID() []byte {
	panic("implement me")
}

func (*emptyEncryptionSetting) IsTokenized() bool {
	return false
}

func (*emptyEncryptionSetting) IsConsistentTokenization() bool {
	panic("implement me")
}

func (*emptyEncryptionSetting) GetTokenType() config.TokenType {
	panic("implement me")
}

func (*emptyEncryptionSetting) IsSearchable() bool {
	return false
}

func (*emptyEncryptionSetting) GetPartialPlaintextLen() int {
	return 0
}

func (*emptyEncryptionSetting) IsEndMasking() bool {
	return false
}
func (*emptyEncryptionSetting) GetMaskingPattern() string {
	return ""
}

func TestAcrawriterDataEncryptor_EncryptWithClientID(t *testing.T) {
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	keystore := &keyStore{keypair: keypair}
	encryptor, err := NewAcrawriterDataEncryptor(keystore)
	if err != nil {
		t.Fatal(err)
	}
	testData := []byte("some raw data")
	encrypted, err := encryptor.EncryptWithClientID([]byte("some id"), testData, &emptyEncryptionSetting{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encrypted, testData) {
		t.Fatal("Data wasn't encrypted")
	}
	if !keystore.clientIDKeyTouched {
		t.Fatal("Wasn't used client id key")
	}

	encrypted, err = encryptor.EncryptWithZoneID([]byte("id"), testData, &emptyEncryptionSetting{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encrypted, testData) {
		t.Fatal("Data wasn't encrypted")
	}
	if !keystore.zoneKeyTouched {
		t.Fatal("Wasn't used zone id key")
	}
}
