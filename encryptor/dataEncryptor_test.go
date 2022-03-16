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
	"errors"
	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/encryptor/config"
	"testing"

	"github.com/cossacklabs/acra/pseudonymization/common"
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

type emptyEncryptionSetting struct{}

func (s *emptyEncryptionSetting) GetDataType() string {
	panic("implement me")
}

func (s *emptyEncryptionSetting) GetDefaultDataValue() *string {
	panic("implement me")
}

func (s *emptyEncryptionSetting) OnlyEncryption() bool {
	return true
}

func (s *emptyEncryptionSetting) GetCryptoEnvelope() config.CryptoEnvelopeType {
	return config.CryptoEnvelopeTypeAcraStruct
}

func (s *emptyEncryptionSetting) ShouldReEncryptAcraStructToAcraBlock() bool {
	panic("implement me")
}

func (s *emptyEncryptionSetting) IsSearchable() bool {
	panic("implement me")
}

func (s *emptyEncryptionSetting) GetMaskingPattern() string {
	panic("implement me")
}

func (s *emptyEncryptionSetting) GetPartialPlaintextLen() int {
	panic("implement me")
}

func (s *emptyEncryptionSetting) IsEndMasking() bool {
	panic("implement me")
}

func (s *emptyEncryptionSetting) IsTokenized() bool {
	panic("implement me")
}

func (s *emptyEncryptionSetting) IsConsistentTokenization() bool {
	panic("implement me")
}

func (s *emptyEncryptionSetting) GetTokenType() common.TokenType {
	panic("implement me")
}

func (*emptyEncryptionSetting) ColumnName() string {
	panic("implement me")
}

func (*emptyEncryptionSetting) ClientID() []byte {
	panic("implement me")
}

func (*emptyEncryptionSetting) ZoneID() []byte {
	panic("implement me")
}

type testChainEncryptor struct {
	expectedData []byte
	returnData   []byte
	err          error
	counter      *int
}

func (t *testChainEncryptor) EncryptWithZoneID(id, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	return t.test(id, data, setting)
}
func (t *testChainEncryptor) test(clientID, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	*t.counter++
	if bytes.Equal(t.expectedData, data) {
		return t.returnData, nil
	}
	return nil, t.err
}

func (t *testChainEncryptor) EncryptWithClientID(id, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	return t.test(id, data, setting)
}

func TestChainDataEncryptorFailure(t *testing.T) {
	testError := errors.New("test error")
	testData := []byte(`test data`)
	startData := []byte(`start data`)
	counter := 0
	encryptor1 := &testChainEncryptor{expectedData: startData, returnData: testData, counter: &counter}
	encryptor2 := &testChainEncryptor{expectedData: testData, returnData: []byte(`blabla`), counter: &counter}
	encryptor3 := &testChainEncryptor{expectedData: nil, err: testError, counter: &counter}
	chainEncryptor := NewChainDataEncryptor(encryptor1, encryptor2, encryptor3)

	type testFunc func(clientID, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error)
	for _, tFunc := range []testFunc{chainEncryptor.EncryptWithClientID, chainEncryptor.EncryptWithZoneID} {
		counter = 0
		output, err := tFunc(nil, startData, nil)
		if err != testError {
			t.Fatalf("Expect %s, took %s\n", testError, err)
		}
		if !bytes.Equal(output, startData) {
			t.Fatalf("Expect startData as data, took %v\nn", output)
		}
		if counter != 3 {
			t.Fatal("Called not all encryptors")
		}
	}
}

func TestChainDataEncryptorSuccess(t *testing.T) {
	testData := []byte(`test data`)
	endData := []byte(`final data`)
	startData := []byte(`start data`)
	counter := 0
	encryptor1 := &testChainEncryptor{expectedData: startData, returnData: testData, counter: &counter}
	encryptor2 := &testChainEncryptor{expectedData: testData, returnData: endData, counter: &counter}
	chainEncryptor := NewChainDataEncryptor(encryptor1, encryptor2)

	type testFunc func(clientID, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error)
	for _, tFunc := range []testFunc{chainEncryptor.EncryptWithClientID, chainEncryptor.EncryptWithZoneID} {
		counter = 0
		output, err := tFunc(nil, startData, nil)
		if err != nil {
			t.Fatalf("Expect nil, took %s\n", err)
		}
		if !bytes.Equal(output, endData) {
			t.Fatalf("Expect endData as data, took %v\nn", output)
		}
		if counter != 2 {
			t.Fatal("Called not all encryptors")
		}
	}
}

func TestAcrawriterDataEncryptor(t *testing.T) {
	testKeyPair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	keyStorage := &keyStore{keypair: testKeyPair}
	testData := []byte(`test data`)
	testAcrastruct, err := acrastruct.CreateAcrastruct(testData, testKeyPair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	encryptor, err := NewAcrawriterDataEncryptor(keyStorage)
	if err != nil {
		t.Fatal(err)
	}
	output, err := encryptor.EncryptWithClientID([]byte(`clientID`), testAcrastruct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output, testAcrastruct) {
		t.Fatalf("Expect untouched acrastruct, took %v\n", output)
	}

	output, err = encryptor.EncryptWithZoneID([]byte(`clientID`), testAcrastruct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output, testAcrastruct) {
		t.Fatalf("Expect untouched acrastruct, took %v\n", output)
	}
}

func TestAcrawriterStandaloneDataEncryptorSkip(t *testing.T) {
	testKeyPair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	keyStorage := &keyStore{keypair: testKeyPair}
	testData := []byte(`test data`)
	testAcrastruct, err := acrastruct.CreateAcrastruct(testData, testKeyPair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	encryptor, err := NewStandaloneDataEncryptor(keyStorage)
	if err != nil {
		t.Fatal(err)
	}
	acrablockEncryption := config.CryptoEnvelopeTypeAcraBlock
	setting := &config.BasicColumnEncryptionSetting{CryptoEnvelope: &acrablockEncryption}
	output, err := encryptor.EncryptWithClientID([]byte(`clientID`), testAcrastruct, setting)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output, testAcrastruct) {
		t.Fatalf("Expect untouched acrastruct, took %v\n", output)
	}

	output, err = encryptor.EncryptWithZoneID([]byte(`clientID`), testAcrastruct, setting)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output, testAcrastruct) {
		t.Fatalf("Expect untouched acrastruct, took %v\n", output)
	}
}
