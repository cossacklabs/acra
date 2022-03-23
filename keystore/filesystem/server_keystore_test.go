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
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	testFilesystemKeyStoreSymmetricWithCache(storage, t)
	testFilesystemKeyStoreRotateZoneKey(storage, t)
	testHistoricalKeyAccess(storage, t)
	testFilesystemKeyStoreWithOnlyCachedData(storage, t)
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

func testGenerateSymKeyUncreatedDir(store *KeyStore, t *testing.T) {
	dir, err := ioutil.TempDir("/tmp", "keys")
	if err != nil {
		t.Fatal(err)
	}
	// ensure we delete dir
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}

	err = store.generateAndSaveSymmetricKey([]byte("key"), fmt.Sprintf("%s/%s", dir, "test_id_sym"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(dir)
	if os.IsNotExist(err) {
		t.Fatal("dir should be created")
	}
}

func testKeyStoreCacheOnStart(store *KeyStore, t *testing.T) {
	clientID := []byte("client_id_with_underscore")
	zoneID := []byte("DDDDDDDDujwBdsnitwoaHEeo")

	if err := store.GenerateClientIDSymmetricKey(clientID); err != nil {
		log.Fatal(err)
	}

	if err := store.GenerateDataEncryptionKeys(clientID); err != nil {
		log.Fatal(err)
	}

	if err := store.GenerateZoneIDSymmetricKey(zoneID); err != nil {
		log.Fatal(err)
	}

	if err := store.GenerateHmacKey(clientID); err != nil {
		log.Fatal(err)
	}

	if err := store.GenerateLogKey(); err != nil {
		log.Fatal(err)
	}

	if err := store.CacheOnStart(); err != nil {
		log.Fatal(err)
	}

	for _, key := range []string{
		"secure_log_key",
		fmt.Sprintf("%s_storage_sym", clientID),
		fmt.Sprintf("%s_storage", clientID),
		fmt.Sprintf("%s_storage.pub", clientID),
		fmt.Sprintf("%s_zone_sym", zoneID),
		fmt.Sprintf("%s_hmac", clientID),
	} {
		err := store.fs.Remove(fmt.Sprintf("%s/%s", store.privateKeyDirectory, key))
		if err != nil && !os.IsNotExist(err) {
			log.Fatal(err)
		}
	}

	// read from cache section
	_, err := store.GetClientIDSymmetricKeys(clientID)
	if err != nil {
		log.Fatal(err)
	}

	_, err = store.GetZoneIDSymmetricKeys(zoneID)
	if err != nil {
		log.Fatal(err)
	}

	_, err = store.GetClientIDEncryptionPublicKey(clientID)
	if err != nil {
		log.Fatal(err)
	}

	_, err = store.GetHMACSecretKey(clientID)
	if err != nil {
		log.Fatal(err)
	}

	_, err = store.GetLogSecretKey()
	if err != nil {
		log.Fatal(err)
	}
}

func testWriteKeyFileUncreatedDir(store *KeyStore, t *testing.T) {
	dir, err := ioutil.TempDir("/tmp", "keys")
	if err != nil {
		t.Fatal(err)
	}
	// ensure we delete dir
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}

	err = store.WriteKeyFile(fmt.Sprintf("%s/%s", dir, "test_id_sym"), []byte("key"), PrivateFileMode)
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(dir)
	if os.IsNotExist(err) {
		t.Fatal("dir should be created")
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

func testGetSymmetricKey(store *KeyStore, t *testing.T) {
	// Insert one clientID key, expect to get it
	testClientID := []byte("client1")
	if err := store.GenerateClientIDSymmetricKey(testClientID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetClientIDSymmetricKey(testClientID); err != nil {
		t.Fatal(err)
	}

	// Insert multiple clientID keys, expect to get 0th one
	testClientID = []byte("client2")
	if err := store.GenerateClientIDSymmetricKey(testClientID); err != nil {
		t.Fatal(err)
	}
	if err := store.GenerateClientIDSymmetricKey(testClientID); err != nil {
		t.Fatal(err)
	}
	encryptionKeys, err := store.GetClientIDSymmetricKeys(testClientID)
	if err != nil {
		t.Fatal(err)
	}
	encryptionKey, err := store.GetClientIDSymmetricKey(testClientID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encryptionKey, encryptionKeys[0]) {
		t.Fatal("store.GetClientIDSymmetricKey() did not return 0th key")
	}

	// Insert one zoneID key, expect to get it
	testZoneID := []byte("zone1")
	if err = store.GenerateClientIDSymmetricKey(testZoneID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.GetClientIDSymmetricKey(testZoneID); err != nil {
		t.Fatal(err)
	}

	// Insert multiple zoneID keys, expect to get 0th one
	testZoneID = []byte("zone2")
	if err = store.GenerateZoneIDSymmetricKey(testZoneID); err != nil {
		t.Fatal(err)
	}
	if err = store.GenerateZoneIDSymmetricKey(testZoneID); err != nil {
		t.Fatal(err)
	}
	encryptionKeys, err = store.GetZoneIDSymmetricKeys(testZoneID)
	if err != nil {
		t.Fatal(err)
	}
	encryptionKey, err = store.GetZoneIDSymmetricKey(testZoneID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encryptionKey, encryptionKeys[0]) {
		t.Fatal("store.GetZoneIDSymmetricKey() did not return 0th key")
	}
}

func testGetPoisonSymmetricKey(store *KeyStore, t *testing.T) {
	poisonKey1, err := store.GetPoisonSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	if len(poisonKey1) != keystore.SymmetricKeyLength {
		t.Fatalf("GetPoisonSymmetricKey() returned encrypted key (%d bytes, expected %d)\n", len(poisonKey1), keystore.SymmetricKeyLength)
	}

	poisonKey2, err := store.GetPoisonSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	if len(poisonKey2) != keystore.SymmetricKeyLength {
		t.Fatalf("GetPoisonSymmetricKey() returned encrypted key (%d bytes, expected %d)\n", len(poisonKey2), keystore.SymmetricKeyLength)
	}

	if !bytes.Equal(poisonKey1, poisonKey2) {
		t.Fatal("Two calls to GetPoisonSymmetricKey() returned different keys")
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
		testGenerateSymKeyUncreatedDir(store, t)
		testWriteKeyFileUncreatedDir(store, t)
		testGetClientIDEncryptionPublicKey(store, t)
		testGetSymmetricKey(store, t)
		testGetPoisonSymmetricKey(store, t)
	}
}

func testFilesystemKeyStoreSymmetricWithCache(storage Storage, t *testing.T) {
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
		// set 3 because 1 key and 2 GetHistoricalFileNames call that cached too
		CacheSize(3).
		Storage(storage).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	// create some key
	testID := []byte("test id")
	if err := store.GenerateClientIDSymmetricKey(testID); err != nil {
		t.Fatal(err)
	}
	// load and save in cache
	_, err = store.GetClientIDSymmetricKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	testID2 := []byte("test id 2")
	// create one more key that shouldn't saved in cache with 1 size
	if err = store.GenerateClientIDSymmetricKey(testID2); err != nil {
		t.Fatal(err)
	}
	// load and save in cache. it must drop previous key from cache
	keys, err := store.GetClientIDSymmetricKeys(testID2)
	if err != nil {
		t.Fatal(err)
	}
	filenames, err := store.GetHistoricalPrivateKeyFilenames(getClientIDSymmetricKeyName(testID))
	if err != nil {
		t.Fatal(err)
	}
	if len(filenames) != 1 {
		t.Fatal("Unexpected amount of filenames")
	}
	// check that previous value was dropped
	value, ok := store.cache.Get(filenames[0])
	if ok {
		t.Fatal("Value wasn't expected")
	}
	if value != nil {
		t.Fatal("Value wasn't expected")
	}
	filenames, err = store.GetHistoricalPrivateKeyFilenames(getClientIDSymmetricKeyName(testID2))
	if err != nil {
		t.Fatal(err)
	}
	if len(filenames) != 1 {
		t.Fatal("Unexpected amount of filenames")
	}
	// check that new values is what we expect: encrypted key
	value, ok = store.cache.Get(filenames[0])
	if !ok {
		t.Fatal("Expected key in result")
	}
	decrypted, err := encryptor.Decrypt(value, testID2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, keys[0]) {
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

func testFilesystemKeyStoreWithOnlyCachedData(storage Storage, t *testing.T) {
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
		CacheSize(keystore.InfiniteCacheSize).
		Storage(storage).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	// generate all kind of keys. Generate twice if keys support rotation to check that cached all keys
	testID := []byte("test id")
	if err := store.GenerateDataEncryptionKeys(testID); err != nil {
		t.Fatal(err)
	}
	if err := store.GenerateDataEncryptionKeys(testID); err != nil {
		t.Fatal(err)
	}

	if err := store.GenerateHmacKey(testID); err != nil {
		t.Fatal(err)
	}
	if err := store.GenerateLogKey(); err != nil {
		t.Fatal(err)
	}
	if err := store.GenerateClientIDSymmetricKey(testID); err != nil {
		t.Fatal(err)
	}
	if err := store.GenerateClientIDSymmetricKey(testID); err != nil {
		t.Fatal(err)
	}
	if err := store.GeneratePoisonRecordSymmetricKey(); err != nil {
		t.Fatal(err)
	}
	if err := store.GeneratePoisonRecordSymmetricKey(); err != nil {
		t.Fatal(err)
	}
	// we don't have public function to generate poison record keypair because it's generated on first fetch operation
	// if they don't exists
	if _, err := store.generateKeyPair(PoisonKeyFilename, []byte(PoisonKeyFilename)); err != nil {
		t.Fatal(err)
	}
	// we don't have public function to generate poison record keypair because it's generated on first fetch operation
	// if they don't exists
	if _, err := store.generateKeyPair(PoisonKeyFilename, []byte(PoisonKeyFilename)); err != nil {
		t.Fatal(err)
	}
	zoneID, _, err := store.GenerateZoneKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RotateZoneKey(zoneID); err != nil {
		t.Fatal(err)
	}
	if err := store.GenerateZoneIDSymmetricKey(zoneID); err != nil {
		t.Fatal(err)
	}
	if err := store.GenerateZoneIDSymmetricKey(zoneID); err != nil {
		t.Fatal(err)
	}

	// fetch keys once to cache backed up keys. due to implementation backed up keys don't stored in cache
	// and put there only after first fetching operation
	_, err = store.GetServerDecryptionPrivateKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetClientIDEncryptionPublicKey(testID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetHMACSecretKey(testID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetLogSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetClientIDSymmetricKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetPoisonSymmetricKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetPoisonPrivateKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetZoneIDSymmetricKeys(zoneID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetZonePrivateKeys(zoneID)
	if err != nil {
		t.Fatal(err)
	}

	// we expect that all keys put in cache after generation. so delete them from storage
	if err := storage.RemoveAll(keyDirectory); err != nil {
		t.Fatal(err)
	}

	// load and save in cache
	privateECKey, err := store.GetServerDecryptionPrivateKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateECKey) != 2 {
		t.Fatal("PrivateEC keys not cached")
	}
	hmacKey, err := store.GetHMACSecretKey(testID)
	if err != nil {
		t.Fatal(err)
	}
	if hmacKey == nil {
		t.Fatal("Hmac key not cached")
	}
	logKey, err := store.GetLogSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	if logKey == nil {
		t.Fatal("log key not cached")
	}

	symKeys, err := store.GetClientIDSymmetricKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	if len(symKeys) != 2 {
		t.Fatal("ClientID sym keys not cached")
	}

	symKeys, err = store.GetPoisonSymmetricKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(symKeys) != 2 {
		t.Fatal("Poison sym keys not cached")
	}

	asymKeys, err := store.GetPoisonPrivateKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(asymKeys) != 2 {
		t.Fatal("Poison asym keys not cached")
	}
	keyPair, err := store.GetPoisonKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if keyPair == nil {
		t.Fatal("Poison keypair not cached")
	}

	asymKeys, err = store.GetZonePrivateKeys(zoneID)
	if err != nil {
		t.Fatal(err)
	}
	if len(asymKeys) != 2 {
		t.Fatal("Zone asym keys not cached")
	}

	symKeys, err = store.GetZoneIDSymmetricKeys(zoneID)
	if err != nil {
		t.Fatal(err)
	}
	if len(symKeys) != 2 {
		t.Fatal("ZoneID sym keys not cached")
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

	// Prepare keystore
	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("test key"))
	if err != nil {
		t.Fatalf("failed to initialize encryptor: %v", err)
	}
	keyStore, err := NewFilesystemKeyStoreTwoPath(privateKeys, publicKeys, encryptor)
	if err != nil {
		t.Fatalf("failed to initialize keystore: %v", err)
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
	// Since we cannot access all generated key pairs via AcraServer keystore,
	// we generate them here and use Save... API
	poisonKeyPair, err := keyStore.GetPoisonKeyPair()
	if err != nil {
		t.Fatalf("GetPoisonKeyPair() failed: %v", err)
	}

	// Test setup complete, now we can finally verify exporting.
	exportedKeys, err := EnumerateExportedKeys(keyStore)
	if err != nil {
		t.Errorf("EnumerateExportedKeys() failed: %v", err)
	}

	seenPoisonKeyPair := false
	seenStorageClientKeyPair := false
	seenStorageZoneKeyPair := false

	for i := range exportedKeys {
		switch exportedKeys[i].Purpose {
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
		default:
			t.Errorf("unknow key purpose: %s", exportedKeys[i].Purpose)
		}
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

// BenchmarkHistoricalPathsSerialization compare simple way of serialization []string into []byte with strings.[Split|Join] and msgpack
// Example of benchmarks to see comparison how msgpack faster simple join/split operations with strings
// goos: linux
// goarch: amd64
// pkg: github.com/cossacklabs/acra/keystore/filesystem
// cpu: Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz
// BenchmarkHistoricalPathsSerialization
// BenchmarkHistoricalPathsSerialization/serialize_with_strings.Split/strings.Join
// BenchmarkHistoricalPathsSerialization/serialize_with_strings.Split/strings.Join-12         	 1000000	      1055 ns/op
// BenchmarkHistoricalPathsSerialization/serialize_with_msgpack
// BenchmarkHistoricalPathsSerialization/serialize_with_msgpack-12                            	1000000000	         0.0000044 ns/op
func BenchmarkHistoricalPathsSerialization(b *testing.B) {
	values := []string{
		"some key 1",
		"some key 2",
		"some key 3",
		"some key 4",
		"some key 5",
	}
	sep := string([]byte{0})
	cacheByJoin := func(paths []string) []byte {
		return []byte(strings.Join(paths, sep))
	}
	getCacheBySplit := func(value []byte) []string {
		return strings.Split(string(value), sep)
	}

	b.Run("serialize with strings.Split/strings.Join", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cached := cacheByJoin(values)
			stringsValue := getCacheBySplit(cached)
			reflect.DeepEqual(stringsValue, values)
		}
	})
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	ks, err := NewCustomFilesystemKeyStore().Encryptor(&dummyEncryptor{}).KeyDirectory(tmpDir).Build()
	if err != nil {
		b.Fatal(err)
	}
	b.Run("serialize with msgpack", func(b *testing.B) {
		if err := ks.cacheHistoricalPrivateKeyFilenames("id", values); err != nil {
			b.Fatal(err)
		}
		paths, err := ks.getCachedHistoricalPrivateKeyFilenames("id")
		if err != nil {
			b.Fatal(err)
		}
		reflect.DeepEqual(paths, values)
	})
}

func TestKeyStore_GetPoisonKeyPair(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	encryptor, err := keystore.NewSCellKeyEncryptor([]byte(`some key`))
	if err != nil {
		t.Fatal(err)
	}
	keyStore, err := NewFilesystemKeyStore(tmpDir, encryptor)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("Check empty cache before generation", func(t *testing.T) {
		_, ok := keyStore.cache.Get(PoisonKeyFilename)
		if ok {
			t.Fatal("Unexpected cached poison private key")
		}
		_, ok = keyStore.cache.Get(poisonKeyFilenamePublic)
		if ok {
			t.Fatal("Unexpected cached poison public key")
		}
	})
	// we don't have api to generate keypair because keystore generates it automatically on first request
	keyPair, err := keyStore.GetPoisonKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("Check caching keys after generation and property that private key encrypted", func(t *testing.T) {
		privateKey, ok := keyStore.cache.Get(PoisonKeyFilename)
		if !ok {
			t.Fatal("Private key wasn't cached")
		}
		if bytes.Equal(privateKey, keyPair.Private.Value) {
			t.Fatal("Cached private key wasn't encrypted and equal to generated raw keypair")
		}
		publicKey, ok := keyStore.cache.Get(poisonKeyFilenamePublic)
		if !ok {
			t.Fatal("Public key wasn't cached")
		}
		if !bytes.Equal(keyPair.Public.Value, publicKey) {
			t.Fatal("Cached public key not equal to raw key")
		}
	})
	t.Run("Check reading keys from the cache after purging keystore folder", func(t *testing.T) {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatal(err)
		}
		keyPair2, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(keyPair2.Public.Value, keyPair.Public.Value) {
			t.Fatal("Took unexpected new keypair's public key")
		}
		if !bytes.Equal(keyPair2.Private.Value, keyPair.Private.Value) {
			t.Fatal("Took unexpected new keypair's private key")
		}
	})
}
