package kms

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSuccessMasterKeyLoading(t *testing.T) {
	kmsKeyManager := &mocks.KeyManager{}

	key := make([]byte, 64)
	_, err := rand.Read(key)
	assert.NoError(t, err)

	masterKey := base64.StdEncoding.EncodeToString(key)

	t.Setenv(keystore.AcraMasterKeyVarName, masterKey)

	kmsKeyManager.On("ID").Return("mocked KMS encryptor")
	kmsKeyManager.On("Decrypt", mock.Anything, []byte(AcraMasterKeyKEKID), key, []byte(nil)).Return([]byte(masterKey), nil)

	kmsLoader := NewLoader(kmsKeyManager)

	loadedMasterKey, err := kmsLoader.LoadMasterKey()
	assert.NoError(t, err)
	assert.Equal(t, masterKey, string(loadedMasterKey))
}
