package acrablock

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/mocks"
	"github.com/cossacklabs/acra/zone"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestNilInputOnColumn(t *testing.T) {
	processor, _ := newDecryptProcessor(t)
	ctx := context.Background()
	_, result, err := processor.OnColumn(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatal("Expect nil in result variable")
	}

}

func newDecryptProcessor(t *testing.T) (*OnColumnProcessor, *mocks.KeyStore) {
	keyStore := mocks.KeyStore{}
	processor, err := NewDecryptProcessor(&keyStore)
	if err != nil {
		t.Fatal(err)
	}
	return NewOnColumnProcessor(processor), &keyStore
}

func TestSuccessDecryptionOnColumn(t *testing.T) {
	symmetricKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	processor, keyStore := newDecryptProcessor(t)
	keyStore.On("GetClientIDSymmetricKeys", mock.Anything).Return([][]byte{symmetricKey}, nil)

	ctx := context.Background()
	testData := make([]byte, 100)
	if _, err = rand.Read(testData); err != nil {
		t.Fatal(err)
	}
	acraBlock, err := CreateAcraBlock(testData, symmetricKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, decrypted, err := processor.OnColumn(ctx, acraBlock)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, testData) {
		t.Fatal("Decrypted data not equal to source data")
	}
}

func TestSuccessDecryptionWithZoneOnColumn(t *testing.T) {
	t.Parallel()
	symmetricKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	processor, keyStore := newDecryptProcessor(t)
	keyStore.On("GetZoneIDSymmetricKeys", mock.Anything).Return([][]byte{symmetricKey}, nil)

	ctx := context.Background()
	testData := make([]byte, 100)
	if _, err = rand.Read(testData); err != nil {
		t.Fatal(err)
	}
	testZone := zone.GenerateZoneID()
	acraBlock, err := CreateAcraBlock(testData, symmetricKey, testZone)
	if err != nil {
		t.Fatal(err)
	}
	accessContext := base.NewAccessContext(base.WithZoneMode(true))
	accessContext.SetZoneID(testZone)
	ctx = base.SetAccessContextToContext(ctx, accessContext)
	_, decrypted, err := processor.OnColumn(ctx, acraBlock)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, testData) {
		t.Fatal("Decrypted data not equal to source data")
	}
}

func TestFailedDecryptionOnColumn(t *testing.T) {
	symmetricKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	processor, keyStore := newDecryptProcessor(t)
	keyStore.On("GetClientIDSymmetricKeys", mock.Anything).Return([][]byte{symmetricKey}, nil)

	ctx := context.Background()
	testData := make([]byte, 100)
	if _, err = rand.Read(testData); err != nil {
		t.Fatal(err)
	}
	symmetricKey2, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	acraBlock, err := CreateAcraBlock(testData, symmetricKey2, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, decrypted, err := processor.OnColumn(ctx, acraBlock)
	if err != nil {
		t.Fatal("Expect nil on decryption with incorrect key")
	}
	if !bytes.Equal(decrypted, acraBlock) {
		t.Fatal("Decrypted data should be equal to AcraBlock, not to source data")
	}
}

func TestFailedDecryptionByKeyStoreOnColumn(t *testing.T) {
	processor, keyStore := newDecryptProcessor(t)
	testError := errors.New("simulate failure on key request from keystore")
	keyStore.On("GetClientIDSymmetricKeys", mock.Anything).Return(nil, testError)
	ctx := context.Background()
	testData := make([]byte, 100)
	if _, err := rand.Read(testData); err != nil {
		t.Fatal(err)
	}
	symmetricKey2, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	acraBlock, err := CreateAcraBlock(testData, symmetricKey2, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, decrypted, err := processor.OnColumn(ctx, acraBlock)
	if err != testError {
		t.Fatal("Expect testError on decryption")
	}
	if !bytes.Equal(decrypted, acraBlock) {
		t.Fatal("Decrypted data should be equal to AcraBlock, not to source data")
	}
}

func TestFailedDecryptionByIncorrectAcraBlockOnColumn(t *testing.T) {
	processor, keyStore := newDecryptProcessor(t)
	testError := errors.New("simulate failure on key request from keystore")
	keyStore.On("GetClientIDSymmetricKeys", mock.Anything).Return(nil, testError)
	ctx := context.Background()
	testData := make([]byte, 100)
	if _, err := rand.Read(testData); err != nil {
		t.Fatal(err)
	}
	symmetricKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	acraBlock, err := CreateAcraBlock(testData, symmetricKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	invalidAcrablock := acraBlock[:len(acraBlock)-5]
	_, decrypted, err := processor.OnColumn(ctx, invalidAcrablock)
	if err != nil {
		t.Fatal("Expect nil on decryption")
	}
	if !bytes.Equal(decrypted, invalidAcrablock) {
		t.Fatal("Decrypted data should be equal to invalid AcraBlock, not to source data")
	}
}

// TestDecryptProcessor_ID just for test coverage for now :) We don't rely on ID in the code, it used just for
// debug purposes in loggers
func TestDecryptProcessor_ID(t *testing.T) {
	processor, _ := newDecryptProcessor(t)
	if processor.ID() != "AcraBlock processor" {
		t.Fatal("Unexpected ID() value")
	}
}

func TestInvalidAcraBlockProcess(t *testing.T) {
	processor, _ := newDecryptProcessor(t)
	testData := make([]byte, 100)
	if _, err := rand.Read(testData); err != nil {
		t.Fatal(err)
	}
	symmetricKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	acraBlock, err := CreateAcraBlock(testData, symmetricKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	invalidAcrablock := acraBlock[:len(acraBlock)-5]
	result, err := processor.processor.Process(invalidAcrablock, &base.DataProcessorContext{})
	if err != ErrInvalidAcraBlock {
		t.Fatal("Expect ErrInvalidAcraBlock")
	}
	if !bytes.Equal(result, invalidAcrablock) {
		t.Fatal("Decrypted data should be equal to invalid AcraBlock, not to source data")
	}
}
