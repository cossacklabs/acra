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

package filesystem

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/themis/gothemis/keys"
)

func TestFilesystemKeyStore(t *testing.T) {
	FilesystemKeyStoreTests(&fileStorage{}, t)
}

func FilesystemKeyStoreTests(storage Storage, t *testing.T) {
	testFilesystemKeyStoreBasic(storage, t)
	testFilesystemKeyStoreWithCache(storage, t)
	testFilesystemKeyStoreRotateZoneKey(storage, t)
	testHistoricalKeyAccess(storage, t)
}

func testGenerateKeyPair(store *KeyStore, t *testing.T) {
	clientID := []byte("some test id")
	// create temp file with random name to use it as not-existed path
	path, err := store.fs.TempFile("test_generate_key_pair", PrivateFileMode)
	if err != nil {
		t.Fatal(err)
	}
	defer store.fs.Remove(path)
	keypair, err := store.generateKeyPair(path, clientID)
	if err != nil {
		t.Fatal(err)
	}
	encryptedKey, err := store.fs.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// check that returned key != stored on filesystem data
	if bytes.Equal(encryptedKey, keypair.Private.Value) {
		t.Fatal("cache are equal")
	}
}

func testGeneral(store *KeyStore, t *testing.T) {
	if store.HasZonePrivateKey([]byte("non-existent key")) {
		t.Fatal("Expected false on non-existent key")
	}
	key, err := store.GetZonePrivateKey([]byte("non-existent key"))
	if err == nil {
		t.Fatal("Expected any error")
	}
	if key != nil {
		t.Fatal("Non-expected key")
	}
	id, _, err := store.GenerateZoneKey()
	if err != nil {
		t.Fatal(err)
	}
	if !store.HasZonePrivateKey(id) {
		t.Fatal("Expected true on existed id")
	}
	key, err = store.GetZonePrivateKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("Expected private key")
	}
}

func testGeneratingDataEncryptionKeys(store *KeyStore, t *testing.T) {
	testID := []byte("test id")
	err := store.GenerateDataEncryptionKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	exists, err := store.fs.Exists(
		store.GetPrivateKeyFilePath(
			GetServerDecryptionKeyFilename(testID)))
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("Private decryption key doesn't exists")
	}

	exists, err = store.fs.Exists(
		fmt.Sprintf("%s.pub", store.GetPublicKeyFilePath(
			GetServerDecryptionKeyFilename(testID))))
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("Public decryption key doesn't exists")
	}
}

func checkPath(store *KeyStore, path string, t *testing.T) {
	exists, err := store.fs.Exists(path)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal(fmt.Sprintf("File <%s> doesn't exists", path))
	}
}

func testGenerateServerKeys(store *KeyStore, t *testing.T) {
	testID := []byte("test id")
	err := store.GenerateServerKeys(testID)
	if err != nil {
		t.Fatal(err)
	}

	absPath := store.GetPrivateKeyFilePath(getServerKeyFilename(testID))
	checkPath(store, absPath, t)
	absPath = store.GetPublicKeyFilePath(fmt.Sprintf("%s.pub", getServerKeyFilename(testID)))
	checkPath(store, absPath, t)
}

func testGenerateTranslatorKeys(store *KeyStore, t *testing.T) {
	testID := []byte("test test id")
	err := store.GenerateTranslatorKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	absPath := store.GetPrivateKeyFilePath(getTranslatorKeyFilename(testID))
	checkPath(store, absPath, t)
	absPath = store.GetPublicKeyFilePath(fmt.Sprintf("%s.pub", getTranslatorKeyFilename(testID)))
	checkPath(store, absPath, t)
}

func testGenerateConnectorKeys(store *KeyStore, t *testing.T) {
	testID := []byte("test id")
	err := store.GenerateConnectorKeys(testID)
	if err != nil {
		t.Fatal(err)
	}

	absPath := store.GetPrivateKeyFilePath(getConnectorKeyFilename(testID))
	checkPath(store, absPath, t)

	absPath = store.GetPublicKeyFilePath(fmt.Sprintf("%s.pub", getConnectorKeyFilename(testID)))
	checkPath(store, absPath, t)

}

func testReset(store *KeyStore, t *testing.T) {
	testID := []byte("some test id")
	if err := store.GenerateServerKeys(testID); err != nil {
		t.Fatal(err)
	}
	if err := store.GenerateTranslatorKeys(testID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPrivateKey(testID); err != nil {
		t.Fatal(err)
	}
	store.Reset()
	if err := store.fs.Remove(store.GetPrivateKeyFilePath(getServerKeyFilename(testID))); err != nil {
		t.Fatal(err)
	}
	if err := store.fs.Remove(fmt.Sprintf("%s.pub", store.GetPublicKeyFilePath(getServerKeyFilename(testID)))); err != nil {
		t.Fatal(err)
	}
	if err := store.fs.Remove(fmt.Sprintf("%s.pub", store.GetPublicKeyFilePath(getTranslatorKeyFilename(testID)))); err != nil {
		t.Fatal(err)
	}

	if _, err := store.GetPrivateKey(testID); err == nil {
		t.Fatal("Expected error on fetching cleared key")
	}
}

func testGetZonePublicKey(store *KeyStore, t *testing.T) {
	id, binPublic, err := store.GenerateZoneKey()
	if err != nil {
		t.Fatal(err)
	}
	public, err := store.GetZonePublicKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(binPublic, public.Value) {
		t.Fatal("Incorrect public key value")
	}
}
func testGetClientIDEncryptionPublicKey(store *KeyStore, t *testing.T) {
	id := []byte("some id")
	if err := store.GenerateDataEncryptionKeys(id); err != nil {
		t.Fatal("Can't generate data encryption keys")
	}
	key, err := store.GetClientIDEncryptionPublicKey(id)
	if err != nil {
		t.Fatal("Can't fetch encryption public key by id")
	}
	if key == nil {
		t.Fatal("Unexpected empty public key")
	}
}

func testFilesystemKeyStoreBasic(storage Storage, t *testing.T) {
	privateKeyDirectory := fmt.Sprintf(".%s%s", string(filepath.Separator), "cache")
	storage.MkdirAll(privateKeyDirectory, 0700)
	defer storage.RemoveAll(privateKeyDirectory)

	publicKeyDirectory := fmt.Sprintf(".%s%s", string(filepath.Separator), "public_keys")
	storage.MkdirAll(publicKeyDirectory, 0700)
	defer storage.RemoveAll(publicKeyDirectory)

	resetKeyFolders := func() {
		storage.RemoveAll(privateKeyDirectory)
		storage.MkdirAll(privateKeyDirectory, 0700)

		storage.RemoveAll(publicKeyDirectory)
		storage.MkdirAll(publicKeyDirectory, 0700)
	}
	resetKeyFolders()

	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("some key"))
	if err != nil {
		t.Fatal(err)
	}
	generalStore, err := NewCustomFilesystemKeyStore().
		KeyDirectory(privateKeyDirectory).
		Encryptor(encryptor).
		Storage(storage).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	splitKeysStore, err := NewCustomFilesystemKeyStore().
		KeyDirectories(privateKeyDirectory, publicKeyDirectory).
		Encryptor(encryptor).
		Storage(storage).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	noCacheKeyStore, err := NewCustomFilesystemKeyStore().
		KeyDirectories(privateKeyDirectory, publicKeyDirectory).
		Encryptor(encryptor).
		CacheSize(keystore.WithoutCache).
		Storage(storage).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	for _, store := range []*KeyStore{generalStore, splitKeysStore, noCacheKeyStore} {
		testGeneral(store, t)
		testGeneratingDataEncryptionKeys(store, t)
		testGenerateConnectorKeys(store, t)
		testGenerateServerKeys(store, t)
		testGenerateTranslatorKeys(store, t)
		testReset(store, t)
		testGenerateKeyPair(store, t)
		testSaveKeypairs(store, t)
		resetKeyFolders()
		testGetZonePublicKey(store, t)
		testGetClientIDEncryptionPublicKey(store, t)
	}
}

func testFilesystemKeyStoreWithCache(storage Storage, t *testing.T) {
	keyDirectory, err := storage.TempDir("test_filesystem_store", keyDirMode)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.RemoveAll(keyDirectory)

	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("some key"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewCustomFilesystemKeyStore().
		KeyDirectory(keyDirectory).
		Encryptor(encryptor).
		CacheSize(1).
		Storage(storage).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	// create some key
	testID := []byte("test id")
	if err := store.GenerateDataEncryptionKeys(testID); err != nil {
		t.Fatal(err)
	}
	// load and save in cache
	_, err = store.GetServerDecryptionPrivateKey(testID)
	if err != nil {
		t.Fatal(err)
	}
	testID2 := []byte("test id 2")
	// create one more key that shouldn't saved in cache with 1 size
	if err = store.GenerateDataEncryptionKeys(testID2); err != nil {
		t.Fatal(err)
	}
	// load and save in cache. it must drop previous key from cache
	privateKey2, err := store.GetServerDecryptionPrivateKey(testID2)
	if err != nil {
		t.Fatal(err)
	}

	// check that previous value was dropped
	value, ok := store.cache.Get(GetServerDecryptionKeyFilename(testID))
	if ok {
		t.Fatal("Value wasn't expected")
	}
	if value != nil {
		t.Fatal("Value wasn't expected")
	}

	// check that new values is what we expect: encrypted key
	value, ok = store.cache.Get(GetServerDecryptionKeyFilename(testID2))
	if !ok {
		t.Fatal("Expected key in result")
	}
	decrypted, err := encryptor.Decrypt(value, testID2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, privateKey2.Value) {
		t.Fatal("Expected correct key in result")
	}

	// check that store created with empty cache
	store, err = NewCustomFilesystemKeyStore().
		KeyDirectory(keyDirectory).
		Encryptor(encryptor).
		CacheSize(keystore.WithoutCache).
		Storage(storage).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.cache.(keystore.NoCache); !ok {
		t.Fatal("KeyStore wasn't created with NoCache implementation")
	}
}

func testFilesystemKeyStoreRotateZoneKey(storage Storage, t *testing.T) {
	keyDirectory, err := storage.TempDir("test_filesystem_store", keyDirMode)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.RemoveAll(keyDirectory)

	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("some key"))
	if err != nil {
		t.Fatal(err)
	}
	keyStore, err := NewCustomFilesystemKeyStore().
		KeyDirectory(keyDirectory).
		Encryptor(encryptor).
		Storage(storage).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	id, publicKey, err := keyStore.GenerateZoneKey()
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := keyStore.GetZonePrivateKey(id)
	if err != nil {
		t.Fatal(err)
	}
	newPublic, err := keyStore.RotateZoneKey(id)
	if err != nil {
		t.Fatal(err)
	}
	rotatedPrivateKey, err := keyStore.GetZonePrivateKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(publicKey, newPublic) {
		t.Fatal("Public key the same as rotated")
	}
	if bytes.Equal(rotatedPrivateKey.Value, privateKey.Value) {
		t.Fatal("Private key the same as rotated")
	}
}

func testSaveKeypairs(store *KeyStore, t *testing.T) {
	store.Reset()
	testID := []byte("testid")
	startKeypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	overwritedKeypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	// no matter which function to generate correct filename we will use
	filename := GetServerDecryptionKeyFilename(testID)
	if _, err := store.getPrivateKeyByFilename(testID, filename); err == nil {
		t.Fatal("Expected error")
	}
	if err = store.SaveKeyPairWithFilename(startKeypair, filename, testID); err != nil {
		t.Fatal(err)
	}
	if privateKey, err := store.getPrivateKeyByFilename(testID, filename); err != nil {
		t.Fatal(err)
	} else {
		if !bytes.Equal(startKeypair.Private.Value, privateKey.Value) {
			t.Fatal("Private key not equal")
		}
	}

	if err = store.SaveKeyPairWithFilename(overwritedKeypair, filename, testID); err != nil {
		t.Fatal(err)
	}
	if privateKey, err := store.getPrivateKeyByFilename(testID, filename); err != nil {
		t.Fatal(err)
	} else {
		if !bytes.Equal(overwritedKeypair.Private.Value, privateKey.Value) {
			t.Fatal("Private key not equal")
		}
	}
}

func TestFilesystemKeyStoreExport(t *testing.T) {
	// Prepare filesystem directory
	keyDirectory, err := ioutil.TempDir(os.TempDir(), "test_filesystem_store")
	if err != nil {
		t.Fatalf("failed to create key directory: %v", err)
	}
	if err = os.Chmod(keyDirectory, 0700); err != nil {
		t.Fatalf("failed to chmod key directory: %v", err)
	}
	defer func() {
		os.RemoveAll(keyDirectory)
	}()
	publicKeys := filepath.Join(keyDirectory, "public")
	privateKeys := filepath.Join(keyDirectory, "private")

	// Prepare key store
	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("test key"))
	if err != nil {
		t.Fatalf("failed to initialize encryptor: %v", err)
	}
	keyStore, err := NewFilesystemKeyStoreTwoPath(privateKeys, publicKeys, encryptor)
	if err != nil {
		t.Fatalf("failed to initialize key store: %v", err)
	}

	// Prepare various keys for testing.
	clientID := []byte("Alice Liddell")

	err = keyStore.GenerateDataEncryptionKeys(clientID)
	if err != nil {
		t.Fatalf("GetZonePublicKey() failed: %v", err)
	}
	storagePublicKey, err := keyStore.GetClientIDEncryptionPublicKey(clientID)
	if err != nil {
		t.Fatalf("GetClientIDEncryptionPublicKey() failed: %v", err)
	}
	storagePrivateKey, err := keyStore.GetServerDecryptionPrivateKey(clientID)
	if err != nil {
		t.Fatalf("GetServerDecryptionPrivateKey() failed: %v", err)
	}
	zoneID, _, err := keyStore.GenerateZoneKey()
	if err != nil {
		t.Fatalf("GenerateZoneKey() failed: %v", err)
	}
	zonePublicKey, err := keyStore.GetZonePublicKey(zoneID)
	if err != nil {
		t.Fatalf("GetZonePublicKey() failed: %v", err)
	}
	zonePrivateKey, err := keyStore.GetZonePrivateKey(zoneID)
	if err != nil {
		t.Fatalf("GetZonePrivateKey() failed: %v", err)
	}
	// Since we cannot access all generated key pairs via AcraServer key store,
	// we generate them here and use Save... API
	connectorKeyPair, err := keys.New(keys.TypeEC)
	err = keyStore.SaveConnectorKeypair(clientID, connectorKeyPair)
	if err != nil {
		t.Fatalf("SaveConnectorKeypair() failed: %v", err)
	}
	serverKeyPair, err := keys.New(keys.TypeEC)
	err = keyStore.SaveServerKeypair(clientID, serverKeyPair)
	if err != nil {
		t.Fatalf("SaveServerKeypair() failed: %v", err)
	}
	translatorKeyPair, err := keys.New(keys.TypeEC)
	err = keyStore.SaveTranslatorKeypair(clientID, translatorKeyPair)
	if err != nil {
		t.Fatalf("SaveTranslatorKeypair() failed: %v", err)
	}
	// And some finishing touches...
	authenticationKey, err := keyStore.GetAuthKey(true)
	if err != nil {
		t.Fatalf("GetAuthKey() failed: %v", err)
	}
	poisonKeyPair, err := keyStore.GetPoisonKeyPair()
	if err != nil {
		t.Fatalf("GetPoisonKeyPair() failed: %v", err)
	}

	// Test setup complete, now we can finally verify exporting.
	exportedKeys, err := EnumerateExportedKeys(keyStore)
	if err != nil {
		t.Errorf("EnumerateExportedKeys() failed: %v", err)
	}

	seenAuthenticationKey := false
	seenPoisonKeyPair := false
	seenStorageClientKeyPair := false
	seenStorageZoneKeyPair := false
	seenTransportConnectorKeyPair := false
	seenTransportTranslatorKeyPair := false
	seenTransportServerKeyPair := false

	for i := range exportedKeys {
		switch exportedKeys[i].Purpose {
		case PurposeAuthenticationSymKey:
			seenAuthenticationKey = true
			storedValue, err := keyStore.ExportPlaintextSymmetricKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPlaintextSymmetricKey() failed: %v", err)
			}
			if !bytes.Equal(authenticationKey, storedValue) {
				t.Error("incorrect authentication key value")
			}
		case PurposePoisonRecordKeyPair:
			seenPoisonKeyPair = true
			publicKey, err := keyStore.ExportPublicKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPublicKey() failed: %v", err)
			}
			privateKey, err := keyStore.ExportPrivateKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPrivateKey() failed: %v", err)
			}
			if !bytes.Equal(poisonKeyPair.Public.Value, publicKey.Value) {
				t.Error("incorrect poison record public key value")
			}
			if !bytes.Equal(poisonKeyPair.Private.Value, privateKey.Value) {
				t.Error("incorrect poison record private key value")
			}
		case PurposeStorageClientKeyPair:
			seenStorageClientKeyPair = true
			publicKey, err := keyStore.ExportPublicKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPublicKey() failed: %v", err)
			}
			privateKey, err := keyStore.ExportPrivateKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPrivateKey() failed: %v", err)
			}
			if !bytes.Equal(storagePublicKey.Value, publicKey.Value) {
				t.Error("incorrect client storage public key value")
			}
			if !bytes.Equal(storagePrivateKey.Value, privateKey.Value) {
				t.Error("incorrect client storage private key value")
			}
		case PurposeStorageZoneKeyPair:
			seenStorageZoneKeyPair = true
			publicKey, err := keyStore.ExportPublicKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPublicKey() failed: %v", err)
			}
			privateKey, err := keyStore.ExportPrivateKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPrivateKey() failed: %v", err)
			}
			if !bytes.Equal(zonePublicKey.Value, publicKey.Value) {
				t.Error("incorrect zone storage public key value")
			}
			if !bytes.Equal(zonePrivateKey.Value, privateKey.Value) {
				t.Error("incorrect zone storage private key value")
			}
		case PurposeTransportConnectorKeyPair:
			seenTransportConnectorKeyPair = true
			publicKey, err := keyStore.ExportPublicKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPublicKey() failed: %v", err)
			}
			privateKey, err := keyStore.ExportPrivateKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPrivateKey() failed: %v", err)
			}
			if !bytes.Equal(connectorKeyPair.Public.Value, publicKey.Value) {
				t.Error("incorrect AcraConnector transport public key value")
			}
			if !bytes.Equal(connectorKeyPair.Private.Value, privateKey.Value) {
				t.Error("incorrect AcraConnector transport private key value")
			}
		case PurposeTransportTranslatorKeyPair:
			seenTransportTranslatorKeyPair = true
			publicKey, err := keyStore.ExportPublicKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPublicKey() failed: %v", err)
			}
			privateKey, err := keyStore.ExportPrivateKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPrivateKey() failed: %v", err)
			}
			if !bytes.Equal(translatorKeyPair.Public.Value, publicKey.Value) {
				t.Error("incorrect AcraTranslator transport public key value")
			}
			if !bytes.Equal(translatorKeyPair.Private.Value, privateKey.Value) {
				t.Error("incorrect AcraTranslator transport private key value")
			}
		case PurposeTransportServerKeyPair:
			seenTransportServerKeyPair = true
			publicKey, err := keyStore.ExportPublicKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPublicKey() failed: %v", err)
			}
			privateKey, err := keyStore.ExportPrivateKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPrivateKey() failed: %v", err)
			}
			if !bytes.Equal(serverKeyPair.Public.Value, publicKey.Value) {
				t.Error("incorrect AcraServer transport public key value")
			}
			if !bytes.Equal(serverKeyPair.Private.Value, privateKey.Value) {
				t.Error("incorrect AcraServer transport private key value")
			}
		default:
			t.Errorf("unknow key purpose: %s", exportedKeys[i].Purpose)
		}
	}

	if !seenAuthenticationKey {
		t.Error("authentication key not exported")
	}
	if !seenPoisonKeyPair {
		t.Error("poison record key pair not exported")
	}
	if !seenStorageClientKeyPair {
		t.Error("storage key for client not expoted")
	}
	if !seenStorageZoneKeyPair {
		t.Error("storage key for zone not exported")
	}
	if !seenTransportConnectorKeyPair {
		t.Error("transport key for AcraConnector not exported")
	}
	if !seenTransportTranslatorKeyPair {
		t.Error("transport key for AcraTranslator not exported")
	}
	if !seenTransportServerKeyPair {
		t.Error("transport key for AcraServer not exported")
	}
}

func testHistoricalKeyAccess(storage Storage, t *testing.T) {
	keyDirectory, err := storage.TempDir("test_filesystem_store", keyDirMode)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.RemoveAll(keyDirectory)

	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("some key"))
	if err != nil {
		t.Fatal(err)
	}
	keyStore, err := NewCustomFilesystemKeyStore().
		KeyDirectory(keyDirectory).
		Encryptor(encryptor).
		Storage(storage).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	id, publicKey1, err := keyStore.GenerateZoneKey()
	if err != nil {
		t.Fatal(err)
	}
	privateKey1, err := keyStore.GetZonePrivateKey(id)
	if err != nil {
		t.Fatal(err)
	}
	publicKey2, err := keyStore.RotateZoneKey(id)
	if err != nil {
		t.Fatal(err)
	}
	privateKey2, err := keyStore.GetZonePrivateKey(id)
	if err != nil {
		t.Fatal(err)
	}
	allPrivateKeys, err := keyStore.GetZonePrivateKeys(id)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(publicKey1, publicKey2) {
		t.Error("rotated public key should not stay the same")
	}
	if bytes.Equal(privateKey1.Value, privateKey2.Value) {
		t.Error("rotated private key should not stay the same")
	}
	if len(allPrivateKeys) != 2 {
		t.Errorf("incorrect total number of private keys: %v", len(allPrivateKeys))
	} else {
		// From newest to oldest
		if !bytes.Equal(allPrivateKeys[0].Value, privateKey2.Value) {
			t.Error("incorrect current private key value")
		}
		if !bytes.Equal(allPrivateKeys[1].Value, privateKey1.Value) {
			t.Error("incorrect previous private key value")
		}
	}
}
