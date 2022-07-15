package kms

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"testing"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSuccessMasterKeyLoading(t *testing.T) {
	kmsEncryptor := &mocks.Keystore{}

	key := make([]byte, 64)
	_, err := rand.Read(key)
	assert.NoError(t, err)

	masterKey := base64.StdEncoding.EncodeToString(key)

	os.Setenv(keystore.AcraMasterKeyVarName, masterKey)
	defer os.Unsetenv(keystore.AcraMasterKeyVarName)

	kmsEncryptor.On("ID").Return("mocked KMS encryptor")
	kmsEncryptor.On("Decrypt", mock.Anything, []byte(AcraMasterKeyKEKID), key, []byte(nil)).Return([]byte(masterKey), nil)

	kmsLoader := NewLoader(kmsEncryptor)

	loadedMasterKey, err := kmsLoader.LoadMasterKey()
	assert.NoError(t, err)
	assert.Equal(t, masterKey, string(loadedMasterKey))
}
