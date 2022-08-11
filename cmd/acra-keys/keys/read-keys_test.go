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
	zoneID := []byte("DDDDDDDDHCzqZAZNbBvybWLR")

	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyEnvMasterKey, keyloader.NewEnvKeyEncryptorFabric(keystore.AcraMasterKeyVarName))
	masterKey, err := keystoreV2.NewSerializedMasterKeys()
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	t.Run("read storage-public key", func(t *testing.T) {
		readCmd := &ReadKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
				keyLoaderOptions: keyloader.CLIOptions{
					KeystoreEncryptorType: keyloader.KeystoreStrategyEnvMasterKey,
				},
			},
			contextID:   clientID,
			readKeyKind: KeyStoragePublic,
		}

		store, err := openKeyStoreV2(readCmd)
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
				keyLoaderOptions: keyloader.CLIOptions{
					KeystoreEncryptorType: keyloader.KeystoreStrategyEnvMasterKey,
				},
			},
			contextID:   clientID,
			readKeyKind: KeySymmetric,
		}

		store, err := openKeyStoreV2(readCmd)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateClientIDSymmetricKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		readCmd.Execute()
	})

	t.Run("read symmetric-zone-key", func(t *testing.T) {
		readCmd := &ReadKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
				keyLoaderOptions: keyloader.CLIOptions{
					KeystoreEncryptorType: keyloader.KeystoreStrategyEnvMasterKey,
				},
			},
			contextID:   zoneID,
			readKeyKind: KeyZoneSymmetric,
		}

		store, err := openKeyStoreV2(readCmd)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateZoneIDSymmetricKey(zoneID)
		if err != nil {
			t.Fatal(err)
		}

		readCmd.Execute()
	})
}

func TestReadCMD_FS_V1(t *testing.T) {
	clientID := []byte("testclientid")
	zoneID := []byte("DDDDDDDDHCzqZAZNbBvybWLR")
	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyEnvMasterKey, keyloader.NewEnvKeyEncryptorFabric(keystore.AcraMasterKeyVarName))

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
				keyLoaderOptions: keyloader.CLIOptions{
					KeystoreEncryptorType: keyloader.KeystoreStrategyEnvMasterKey,
				},
			},
			contextID:   clientID,
			readKeyKind: KeyStoragePublic,
		}

		store, err := openKeyStoreV1(readCmd)
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
				keyLoaderOptions: keyloader.CLIOptions{
					KeystoreEncryptorType: keyloader.KeystoreStrategyEnvMasterKey,
				},
			},
			contextID:   clientID,
			readKeyKind: KeySymmetric,
		}

		store, err := openKeyStoreV1(readCmd)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateClientIDSymmetricKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		readCmd.Execute()
	})

	t.Run("read symmetric-zone-key", func(t *testing.T) {
		readCmd := &ReadKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
				keyLoaderOptions: keyloader.CLIOptions{
					KeystoreEncryptorType: keyloader.KeystoreStrategyEnvMasterKey,
				},
			},
			contextID:   zoneID,
			readKeyKind: KeyZoneSymmetric,
		}

		store, err := openKeyStoreV1(readCmd)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateZoneIDSymmetricKey(zoneID)
		if err != nil {
			t.Fatal(err)
		}

		readCmd.Execute()
	})
}
