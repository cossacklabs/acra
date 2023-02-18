package keystore

import (
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func GetNewDefaultKeystore(t *testing.T) keystore.ServerKeyStore {
	keystoreDir, err := os.MkdirTemp("", "")
	assert.Nil(t, err)
	keyEncryptor, err := keystore.NewSCellKeyEncryptor([]byte(`key`))
	assert.Nil(t, err)
	keyStore := filesystem.NewCustomFilesystemKeyStore()
	keyStore.KeyDirectory(keystoreDir)
	keyStore.CacheSize(0)
	keyStore.Encryptor(keyEncryptor)
	serverKeystore, err := keyStore.Build()
	assert.Nil(t, err)
	return serverKeystore
}
