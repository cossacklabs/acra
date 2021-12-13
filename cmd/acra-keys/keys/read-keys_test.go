package keys

import (
	"encoding/base64"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/keyloader"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
)

func TestReadCMD_FS_V2(t *testing.T) {
	dirName, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dirName)

	clientID := []byte("testclientid")
	keyLoader := keyloader.NewEnvLoader(keystore.AcraMasterKeyVarName)

	masterKey, err := keystoreV2.NewSerializedMasterKeys()
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	t.Run("read storage-public key", func(t *testing.T) {
		readCmd := &ReadKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			contextID:   clientID,
			readKeyKind: KeyStoragePublic,
		}

		store, err := openKeyStoreV2(readCmd, keyLoader)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateDataEncryptionKeys(clientID)
		if err != nil {
			t.Fatal(err)
		}

		readCmd.Execute()
	})

	t.Run("read symmetric-key", func(t *testing.T) {
		readCmd := &ReadKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			contextID:   clientID,
			readKeyKind: KeySymmetric,
		}

		store, err := openKeyStoreV2(readCmd, keyLoader)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateClientIDSymmetricKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		readCmd.Execute()
	})
}

func TestReadCMD_FS_V1(t *testing.T) {
	clientID := []byte("testclientid")
	keyLoader := keyloader.NewEnvLoader(keystore.AcraMasterKeyVarName)

	masterKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	dirName, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dirName)

	t.Run("read storage-public key", func(t *testing.T) {
		readCmd := &ReadKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			contextID:   clientID,
			readKeyKind: KeyStoragePublic,
		}

		store, err := openKeyStoreV1(readCmd, keyLoader)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateDataEncryptionKeys(clientID)
		if err != nil {
			t.Fatal(err)
		}

		readCmd.Execute()
	})

	t.Run("read symmetric-key", func(t *testing.T) {
		readCmd := &ReadKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			contextID:   clientID,
			readKeyKind: KeySymmetric,
		}

		store, err := openKeyStoreV1(readCmd, keyLoader)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateClientIDSymmetricKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		readCmd.Execute()
	})
}
