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

package acrablock

import (
	"bytes"
	"errors"
	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/keystore"
	"math/rand"
	"testing"

	"github.com/cossacklabs/themis/gothemis/keys"
)

func testAcraBlock() error {
	type testcase struct {
		Data               []byte
		Context            []byte
		Keys               [][]byte
		EncryptionKeyIndex int
	}
	testCases := []testcase{
		// without context with "last" key usage
		{
			Data:               []byte(`some data1`),
			Context:            nil,
			Keys:               [][]byte{[]byte(`key2`), []byte(`key3`)},
			EncryptionKeyIndex: 0,
		},
		// without context with "old" key usage
		{
			Data:               []byte(`some data4`),
			Context:            nil,
			Keys:               [][]byte{[]byte(`key5`), []byte(`key6`)},
			EncryptionKeyIndex: 1,
		},
		// with context with "last" key usage
		{
			Data:               []byte(`some data7`),
			Context:            []byte(`some context8`),
			Keys:               [][]byte{[]byte(`key9`), []byte(`key10`)},
			EncryptionKeyIndex: 0,
		},
		// with context with "old" key usage
		{
			Data:               []byte(`some data11`),
			Context:            []byte(`some context12`),
			Keys:               [][]byte{[]byte(`key13`), []byte(`key14`)},
			EncryptionKeyIndex: 1,
		},
	}

	for _, tcase := range testCases {
		rawAcraBlock, err := CreateAcraBlock(tcase.Data, tcase.Keys[tcase.EncryptionKeyIndex], tcase.Context)
		if err != nil {
			return err
		}

		acraBlock, err := NewAcraBlockFromData(rawAcraBlock)
		if err != nil {
			return err
		}
		decryptedData, err := acraBlock.Decrypt(tcase.Keys, tcase.Context)
		if err != nil {
			return err
		}
		if !bytes.Equal(decryptedData, tcase.Data) {
			return errors.New("decrypted data not equal with source data")
		}
	}
	return nil
}

func TestAcraBlock(t *testing.T) {
	err := testAcraBlock()
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkAcraBlock(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if err := testAcraBlock(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAcraStruct(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if err := testAcraStruct(); err != nil {
			b.Fatal(err)
		}
	}
}

func testAcraStruct() error {
	keypairs := make([]*keys.Keypair, 0, 8)
	for i := 0; i < 8; i++ {
		kp, err := keys.New(keys.TypeEC)
		if err != nil {
			return err
		}
		keypairs = append(keypairs, kp)
	}
	type testcase struct {
		Data               []byte
		Context            []byte
		Keys               []*keys.Keypair
		EncryptionKeyIndex int
	}
	testCases := []testcase{
		// without context with "last" key usage
		{
			Data:               []byte(`some data1`),
			Context:            nil,
			Keys:               []*keys.Keypair{keypairs[0], keypairs[1]},
			EncryptionKeyIndex: 0,
		},
		// without context with "old" key usage
		{
			Data:               []byte(`some data4`),
			Context:            nil,
			Keys:               []*keys.Keypair{keypairs[2], keypairs[3]},
			EncryptionKeyIndex: 1,
		},
		// with context with "last" key usage
		{
			Data:               []byte(`some data7`),
			Context:            []byte(`some context8`),
			Keys:               []*keys.Keypair{keypairs[4], keypairs[5]},
			EncryptionKeyIndex: 0,
		},
		// with context with "old" key usage
		{
			Data:               []byte(`some data11`),
			Context:            []byte(`some context12`),
			Keys:               []*keys.Keypair{keypairs[6], keypairs[7]},
			EncryptionKeyIndex: 1,
		},
	}
	getPrivateKeys := func(keypairs []*keys.Keypair) []*keys.PrivateKey {
		out := make([]*keys.PrivateKey, 0, len(keypairs))
		for _, k := range keypairs {
			out = append(out, &keys.PrivateKey{Value: k.Private.Value})
		}
		return out
	}
	for _, tcase := range testCases {
		rawAcraBlock, err := acrastruct.CreateAcrastruct(tcase.Data, tcase.Keys[tcase.EncryptionKeyIndex].Public, tcase.Context)
		if err != nil {
			return err
		}
		decryptedData, err := acrastruct.DecryptRotatedAcrastruct(rawAcraBlock, getPrivateKeys(tcase.Keys), tcase.Context)
		if err != nil {
			return err
		}
		if !bytes.Equal(decryptedData, tcase.Data) {
			return errors.New("decrypted data not equal with source data")
		}
	}
	return nil
}

func TestAcraStruct(t *testing.T) {
	if err := testAcraStruct(); err != nil {
		t.Fatal(err)
	}
}

func TestFailureExtractAcraBlockFromData(t *testing.T) {
	n, acraBlock, err := ExtractAcraBlockFromData([]byte(`some data`))
	if n != 0 {
		t.Fatal("Expect 0 from result length of AcraBlock")
	}
	if acraBlock != nil {
		t.Fatal("Expect nil from result AcraBlock on non-AcraBlock input")
	}
	if err != ErrInvalidAcraBlock {
		t.Fatal("Expect ErrInvalidAcraBlock on non-AcraBlock input")
	}
}

type errorKeyGenerator struct {
	err error
}

func (e errorKeyGenerator) GenerateKeyID(key, context []byte) ([]byte, error) {
	return nil, e.err
}

func TestFailedSetKeyEncryptionType(t *testing.T) {
	acraBlock := AcraBlock{}
	expectedErr := errors.New("some error")
	err := acraBlock.SetKeyEncryptionKeyID(nil, nil, errorKeyGenerator{expectedErr})
	if err != expectedErr {
		t.Fatal("Expect expectedErr on SetKeyEncryptionKeyID call")
	}
}
func TestFailedSetEncryptedKey(t *testing.T) {
	err := AcraBlock{}.setEncryptedDataEncryptionKey([]byte{1})
	if err != ErrInvalidAcraBlock {
		t.Fatal("Expect ErrInvalidAcraBlock on setEncryptedDataEncryptionKey call with short AcraBlock")
	}
}

func TestSetEncryptedDataToInvalidAcraBlock(t *testing.T) {
	err := AcraBlock{}.setEncryptedData(nil)
	if err != ErrInvalidAcraBlock {
		t.Fatal("Expect ErrInvalidAcraBlock on setEncryptedData call with invalid AcraBlock")
	}
}

func TestSetEncryptedDataToShortForKeyInvalidAcraBlock(t *testing.T) {
	testKey := make([]byte, 1, 1)
	acraBlock := NewEmptyAcraBlock(100)
	// save key and keysize
	if err := acraBlock.setEncryptedDataEncryptionKey(testKey); err != nil {
		t.Fatal(err)
	}
	shortAcraBlock := AcraBlock(make([]byte, DataEncryptionKeyLengthPosition+DataEncryptionKeyLengthSize))
	copy(shortAcraBlock, acraBlock)

	err := shortAcraBlock.setEncryptedData([]byte{1})
	if err != ErrInvalidAcraBlock {
		t.Fatal("Expect ErrInvalidAcraBlock on setEncryptedData call with invalid AcraBlock")
	}
}

func TestSetEncryptedDataToShortForDataInvalidAcraBlock(t *testing.T) {
	testKey := make([]byte, 1, 1)
	acraBlock := NewEmptyAcraBlock(100)
	// save key and keysize
	if err := acraBlock.setEncryptedDataEncryptionKey(testKey); err != nil {
		t.Fatal(err)
	}
	shortAcraBlock := AcraBlock(make([]byte, EncryptedDataEncryptionKeyPosition+len(testKey)))
	copy(shortAcraBlock, acraBlock)

	err := shortAcraBlock.setEncryptedData([]byte{1})
	if err != ErrInvalidAcraBlock {
		t.Fatal("Expect ErrInvalidAcraBlock on setEncryptedData call with invalid AcraBlock")
	}
}

func TestFailedBuildWithShortAcraBlockAndEncryptionKey(t *testing.T) {
	data, err := AcraBlock{}.Build([]byte{1}, nil)
	if data != nil {
		t.Fatal("Unexpected data on invalid Build call")
	}
	if err != ErrInvalidAcraBlock {
		t.Fatal("Expect ErrInvalidAcraBlock on Build call over short AcraBlock on " +
			"internal setEncryptedDataEncryptionKey call")
	}
}

func TestFailedBuildWithShortAcraBlockAndEncryptedData(t *testing.T) {
	shortAcraBlock := AcraBlock(make([]byte, EncryptedDataEncryptionKeyPosition))
	data, err := shortAcraBlock.Build(nil, []byte{1})
	if data != nil {
		t.Fatal("Unexpected data on invalid Build call")
	}
	if err != ErrInvalidAcraBlock {
		t.Fatal("Expect ErrInvalidAcraBlock on Build call over short AcraBlock on " +
			"internal setEncryptedData call")
	}
}

func TestFailedDecryptionOnInvalidEncryptedData(t *testing.T) {
	key := []byte{1}
	encryptedAcraBlock, err := CreateAcraBlock([]byte{1}, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	// corrupt acraBlock by changing value of last byte
	encryptedAcraBlock[len(encryptedAcraBlock)-1]++
	acraBlock, err := NewAcraBlockFromData(encryptedAcraBlock)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := acraBlock.Decrypt([][]byte{key}, nil)
	if err != ErrInvalidAcraBlock {
		t.Fatal("Expect ErrInvalidAcraBlock on decryption corrupted encrypted data with correct key")
	}
	if decrypted != nil {
		t.Fatal("Expect nil from result on failed decryption")
	}
}

type testKeyEncryptionBackend struct {
	called int
}

func (t *testKeyEncryptionBackend) Encrypt(key []byte, data []byte, context []byte) ([]byte, error) {
	return SecureCellSymmetricBackend{}.Encrypt(key, data, context)
}

func (t *testKeyEncryptionBackend) Decrypt(key []byte, data []byte, context []byte) ([]byte, error) {
	t.called++
	return SecureCellSymmetricBackend{}.Decrypt(key, data, context)
}

func TestAcraBlockKeyIDUsage(t *testing.T) {
	count := 10
	symKeys := make([][]byte, count)
	keysHashes := make(map[string]int, count)
	// create <count> new random sym keys
	// remember how much keys with same KeyID because of used only first 2 bytes of hash and there may be collision
	for i := 0; i < count; i++ {
		key, err := keystore.GenerateSymmetricKey()
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := Sha256KeyIDGenerator{}.GenerateKeyID(key, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, ok := keysHashes[string(keyID[:KeyEncryptionKeyIDSize])]
		if ok {
			keysHashes[string(keyID[:KeyEncryptionKeyIDSize])]++
		} else {
			keysHashes[string(keyID[:KeyEncryptionKeyIDSize])] = 1
		}
		symKeys[i] = key
	}
	// use last key in a sequence to force decryptor to iterate through all keys
	testKey := symKeys[len(symKeys)-1]
	testData := []byte(`some data`)
	backend := &testKeyEncryptionBackend{}
	// get new random ID for test backend, check that it's not used already and register our test backed
	var backendID int
	for {
		backendID = rand.Int()
		_, ok := keyEncryptionBackendTypeMap[KeyEncryptionBackendType(backendID)]
		if ok {
			continue
		}
		keyEncryptionBackendTypeMap[KeyEncryptionBackendType(backendID)] = backend
		break
	}
	// unregister test backend at end
	defer delete(keyEncryptionBackendTypeMap, KeyEncryptionBackendType(backendID))

	// use last key in keychain
	acraBlockData, err := CreateAcraBlockWithBackends(testData, testKey, nil, KeyEncryptionBackendType(backendID), defaultDataEncryptionBackendType)
	if err != nil {
		t.Fatal(err)
	}
	acraBlock, err := NewAcraBlockFromData(acraBlockData)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := acraBlock.Decrypt(symKeys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, testData) {
		t.Fatal("Decrypted data not equal to source data")
	}
	testKeyID, err := Sha256KeyIDGenerator{}.GenerateKeyID(testKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	// get amount of keys with same ID (because there may be other keys with same ID sometimes) and check
	// that decryptor tried to decrypt not all keys, only with matched ID
	expectedKeyUsage := keysHashes[string(testKeyID[:KeyEncryptionKeyIDSize])]
	// we don't believe that all keys has same keyID
	if expectedKeyUsage == len(symKeys) {
		t.Fatal("Something wrong with keys generation or keyID counting")
	}
	if backend.called != expectedKeyUsage {
		t.Fatal("Incorrect count of key decryption")
	}
}

func TestPrefixedAcraBlockExtraction(t *testing.T) {
	testData := []byte(`test data`)
	encryptedData, err := CreateAcraBlock(testData, []byte(`key`), nil)
	if err != nil {
		t.Fatal(err)
	}
	extraData := []byte(`some extra data`)
	prefixedEncrypted := append(encryptedData, extraData...)
	n, acraBlock, err := ExtractAcraBlockFromData(prefixedEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(encryptedData) {
		t.Fatalf("Incorrect length of extracted AcraBlock. Expect %d, took %d\n", len(encryptedData), n)
	}
	if !bytes.Equal(acraBlock, encryptedData) {
		t.Fatal("Extracted AcraBlock != prefixed AcraBlock")
	}
}
