package kms

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"testing"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/kms"
	"github.com/cossacklabs/acra/keystore/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSuccessMasterKeyLoading(t *testing.T) {
	kmsEncryptor := &mocks.Encryptor{}

	key := make([]byte, 64)
	_, err := rand.Read(key)
	assert.NoError(t, err)

	masterKey := base64.StdEncoding.EncodeToString(key)

	os.Setenv(keystore.AcraMasterKeyVarName, masterKey)
	defer os.Unsetenv(keystore.AcraMasterKeyVarName)

	kmsEncryptor.On("ID").Return("mocked KMS encryptor")
	kmsEncryptor.On("Decrypt", mock.Anything, kms.AcraMasterKeyKEKID, key).Return([]byte(masterKey), nil)

	encryptorCreator := func(path string) (kms.Encryptor, error) {
		return kmsEncryptor, nil
	}
	kms.RegisterEncryptorCreator(kms.TypeAWS, encryptorCreator)

	kmsLoader, err := NewLoader("config.json", kms.TypeAWS)
	assert.NoError(t, err)

	loadedMasterKey, err := kmsLoader.LoadMasterKey()
	assert.NoError(t, err)
	assert.Equal(t, masterKey, string(loadedMasterKey))
}
