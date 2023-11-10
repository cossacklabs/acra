package acrablock

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cossacklabs/themis/gothemis/keys"

	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/mocks"
)

func TestSuccessDataEncryptionWithClientID(t *testing.T) {
	keyStore := mocks.ServerKeyStore{}
	dataEncryptor, err := NewDataEncryptor(&keyStore)
	if err != nil {
		t.Fatal(err)
	}
	symKey := []byte(`some key`)
	clientID := []byte(`clientid`)
	keyStore.On("GetClientIDSymmetricKey", clientID).Return(symKey, nil)
	envelopeType := config.CryptoEnvelopeTypeAcraBlock
	setting := &config.BasicColumnEncryptionSetting{CryptoEnvelope: &envelopeType}
	testData := []byte(`test data`)
	encrypted, err := dataEncryptor.EncryptWithClientID(clientID, testData, setting)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encrypted, testData) {
		t.Fatal("Source data == encrypted data, it is incorrect behaviour")
	}
	n, acraBlock, err := ExtractAcraBlockFromData(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if acraBlock == nil {
		t.Fatal("Expect valid AcraBlock after encryption")
	}
	if n != len(acraBlock) {
		t.Fatal("Took invalid AcraBlock with extra data")
	}
	decrypted, err := acraBlock.Decrypt([][]byte{symKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, testData) {
		t.Fatal("Decrypted data != testData")
	}
}

func TestSuccessAcraStructReEncryptionWithClientID(t *testing.T) {
	testData := []byte(`test data`)
	keyPair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	acraStruct, err := acrastruct.CreateAcrastruct(testData, keyPair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyStore := mocks.ServerKeyStore{}
	dataEncryptor, err := NewDataEncryptor(&keyStore)
	if err != nil {
		t.Fatal(err)
	}
	symKey := []byte(`some key`)
	clientID := []byte(`clientid`)
	keyStore.On("GetClientIDSymmetricKeys", clientID).Return([][]byte{symKey}, nil)
	keyStore.On("GetClientIDSymmetricKey", clientID).Return(symKey, nil)
	keyStore.On("GetServerDecryptionPrivateKeys", clientID).Return([]*keys.PrivateKey{keyPair.Private}, nil)

	envelopeType := config.CryptoEnvelopeTypeAcraBlock
	reEncrypt := true
	setting := &config.BasicColumnEncryptionSetting{CryptoEnvelope: &envelopeType, ReEncryptToAcraBlock: &reEncrypt}
	encrypted, err := dataEncryptor.EncryptWithClientID(clientID, acraStruct, setting)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encrypted, testData) {
		t.Fatal("Source data == encrypted data, it is incorrect behaviour")
	}
	n, acraBlock, err := ExtractAcraBlockFromData(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if acraBlock == nil {
		t.Fatal("Expect valid AcraBlock after encryption")
	}
	if n != len(acraBlock) {
		t.Fatal("Took invalid AcraBlock with extra data")
	}
	decrypted, err := acraBlock.Decrypt([][]byte{symKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, testData) {
		t.Fatal("Decrypted data != testData")
	}
}

func TestSuccessIgnoringAcraStructReEncryptionWithClientID(t *testing.T) {
	testData := []byte(`test data`)
	keyPair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	acraStruct, err := acrastruct.CreateAcrastruct(testData, keyPair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyStore := mocks.ServerKeyStore{}
	dataEncryptor, err := NewDataEncryptor(&keyStore)
	if err != nil {
		t.Fatal(err)
	}
	symKey := []byte(`some key`)
	clientID := []byte(`clientid`)
	keyStore.On("GetClientIDSymmetricKeys", clientID).Return([][]byte{symKey}, nil)
	keyStore.On("GetClientIDSymmetricKey", clientID).Return(symKey, nil)
	keyStore.On("GetServerDecryptionPrivateKeys", clientID).Return([]*keys.PrivateKey{keyPair.Private}, nil)

	envelopeType := config.CryptoEnvelopeTypeAcraBlock
	reEncrypt := false
	setting := &config.BasicColumnEncryptionSetting{CryptoEnvelope: &envelopeType, ReEncryptToAcraBlock: &reEncrypt}
	encrypted, err := dataEncryptor.EncryptWithClientID(clientID, acraStruct, setting)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encrypted, testData) {
		t.Fatal("Source data == encrypted data, it is incorrect behaviour")
	}
	n, acraBlock, err := ExtractAcraBlockFromData(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if acraBlock == nil {
		t.Fatal("Expect valid AcraBlock after encryption")
	}
	if n != len(acraBlock) {
		t.Fatal("Took invalid AcraBlock with extra data")
	}
	decrypted, err := acraBlock.Decrypt([][]byte{symKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, acraStruct) {
		t.Fatal("Decrypted data != testData")
	}
}

func TestFailedCorruptedAcraStructReEncryptionWithClientID(t *testing.T) {
	testData := []byte(`test data`)
	keyPair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	acraStruct, err := acrastruct.CreateAcrastruct(testData, keyPair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyStore := mocks.ServerKeyStore{}
	dataEncryptor, err := NewDataEncryptor(&keyStore)
	if err != nil {
		t.Fatal(err)
	}
	symKey := [][]byte{[]byte(`some key`)}
	clientID := []byte(`clientid`)
	keyStore.On("GetClientIDSymmetricKeys", clientID).Return(symKey, nil)
	keyStore.On("GetServerDecryptionPrivateKeys", clientID).Return([]*keys.PrivateKey{keyPair.Private}, nil)

	envelopeType := config.CryptoEnvelopeTypeAcraBlock
	reEncrypt := true
	setting := &config.BasicColumnEncryptionSetting{CryptoEnvelope: &envelopeType, ReEncryptToAcraBlock: &reEncrypt}
	// corrupt AcraStruct
	acraStruct[len(acraStruct)-1]++
	encrypted, err := dataEncryptor.EncryptWithClientID(clientID, acraStruct, setting)
	if err == nil {
		t.Fatal("Expect error on EncryptWithClientID with corrupted AcraStruct")
	}
	if !bytes.Equal(encrypted, acraStruct) {
		t.Fatal("Expect that data result will be same as source data")
	}
}

func TestSkipDataEncryptionForAcraBlock(t *testing.T) {
	symKey := [][]byte{[]byte(`some key`)}
	testData := []byte(`some data`)

	keyStore := mocks.ServerKeyStore{}
	dataEncryptor, err := NewDataEncryptor(&keyStore)
	if err != nil {
		t.Fatal(err)
	}

	acraBlock, err := CreateAcraBlock(testData, symKey[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	envelopeType := config.CryptoEnvelopeTypeAcraBlock
	setting := &config.BasicColumnEncryptionSetting{CryptoEnvelope: &envelopeType}
	encrypted, err := dataEncryptor.EncryptWithClientID(nil, acraBlock, setting)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encrypted, acraBlock) {
		t.Fatal("Expect that encryption will be skipped for AcraBlock")
	}
}

func TestSkipDataEncryptionWithoutConfiguredSetting(t *testing.T) {
	dataEncryptor, err := NewStandaloneDataEncryptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	envelopeType := config.CryptoEnvelopeTypeAcraStruct
	setting := &config.BasicColumnEncryptionSetting{CryptoEnvelope: &envelopeType}
	expectedData := []byte(`some data`)
	encrypted, err := dataEncryptor.EncryptWithClientID(nil, expectedData, setting)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encrypted, expectedData) {
		t.Fatal("Expect that data result will be same as source data")
	}
}

func TestFailedDataEncryptionWithErrorFromKeystore(t *testing.T) {
	keyStore := mocks.ServerKeyStore{}
	dataEncryptor, err := NewDataEncryptor(&keyStore)
	if err != nil {
		t.Fatal(err)
	}
	expectedError := errors.New("some error")
	clientID := []byte(`clientid`)
	keyStore.On("GetClientIDSymmetricKey", clientID).Return(nil, expectedError)
	envelopeType := config.CryptoEnvelopeTypeAcraBlock
	setting := &config.BasicColumnEncryptionSetting{CryptoEnvelope: &envelopeType}
	testData := []byte(`test data`)

	encrypted, err := dataEncryptor.EncryptWithClientID(clientID, testData, setting)
	if err != expectedError {
		t.Fatal("Expect expectedError on EncryptWithClientID call")
	}
	if !bytes.Equal(encrypted, testData) {
		t.Fatal("Expect that data result will be same as source data")
	}
}

func TestFailedDataEncryptionOnEmptyKeys(t *testing.T) {
	keyStore := mocks.ServerKeyStore{}
	dataEncryptor, err := NewDataEncryptor(&keyStore)
	if err != nil {
		t.Fatal(err)
	}
	clientID := []byte(`clientid`)
	keyStore.On("GetClientIDSymmetricKey", clientID).Return(nil, keystore.ErrKeysNotFound)
	envelopeType := config.CryptoEnvelopeTypeAcraBlock
	setting := &config.BasicColumnEncryptionSetting{CryptoEnvelope: &envelopeType}
	testData := []byte(`test data`)

	encrypted, err := dataEncryptor.EncryptWithClientID(clientID, testData, setting)
	if err != keystore.ErrKeysNotFound {
		t.Fatal("Expect keystore.ErrKeysNotFound on EncryptWithClientID call")
	}
	if !bytes.Equal(encrypted, testData) {
		t.Fatal("Expect that data result will be same as source data")
	}
}
