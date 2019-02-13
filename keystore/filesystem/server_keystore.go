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

// Package filesystem implements keystores that write and reads keys from file system. Each keystore is responsible
// for generating keys for specific service, writing them to provided file path, reading and decrypting them.
// Server keystore generates AcraServer transport key pair and AcraStorage encryption keypair used for
// creating/decrypting AcraStructs.
// Connector keystore generates AcraConnector transport key pair.
// Translator keystore generates AcraTranslator transport key pair.
//
// https://github.com/cossacklabs/acra/wiki/Key-Management
package filesystem

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/lru"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// PrivateFileMode used for all created files with private data
const PrivateFileMode = os.FileMode(0600)

// KeyStore represents keystore that reads keys from key folders, and stores them in memory.
type KeyStore struct {
	cache               keystore.Cache
	privateKeyDirectory string
	publicKeyDirectory  string
	lock                *sync.RWMutex
	encryptor           keystore.KeyEncryptor
}

// NewFileSystemKeyStoreWithCacheSize represents keystore that reads keys from key folders, and stores them in cache.
func NewFileSystemKeyStoreWithCacheSize(directory string, encryptor keystore.KeyEncryptor, cacheSize int) (*KeyStore, error) {
	return newFilesystemKeyStore(directory, directory, encryptor, cacheSize)
}

// NewFilesystemKeyStore represents keystore that reads keys from key folders, and stores them in memory.
func NewFilesystemKeyStore(directory string, encryptor keystore.KeyEncryptor) (*KeyStore, error) {
	return newFilesystemKeyStore(directory, directory, encryptor, keystore.InfiniteCacheSize)
}

// NewFilesystemKeyStoreTwoPath creates new KeyStore using separate folders for private and public keys.
func NewFilesystemKeyStoreTwoPath(privateKeyFolder, publicKeyFolder string, encryptor keystore.KeyEncryptor) (*KeyStore, error) {
	return newFilesystemKeyStore(privateKeyFolder, publicKeyFolder, encryptor, keystore.InfiniteCacheSize)
}

func newFilesystemKeyStore(privateKeyFolder, publicKeyFolder string, encryptor keystore.KeyEncryptor, cacheSize int) (*KeyStore, error) {
	// check folder for private key
	directory, err := filepath.Abs(privateKeyFolder)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(directory)
	const expectedPermission = "-rwx------"
	if nil == err && runtime.GOOS == "linux" && fi.Mode().Perm().String() != expectedPermission {
		log.Errorf("Key store folder has an incorrect permissions %s, expected: %s", fi.Mode().Perm().String(), expectedPermission)
		return nil, errors.New("key store folder has an incorrect permissions")
	}
	if privateKeyFolder != publicKeyFolder {
		// check folder for public key
		directory, err = filepath.Abs(privateKeyFolder)
		if err != nil {
			return nil, err
		}
		fi, err = os.Stat(directory)
		if nil != err && !os.IsNotExist(err) {
			return nil, err
		}
	}
	var cache keystore.Cache
	if cacheSize == keystore.WithoutCache {
		cache = keystore.NoCache{}
	} else {
		cache, err = lru.NewCacheKeystoreWrapper(cacheSize)
		if err != nil {
			return nil, err
		}
	}
	store := &KeyStore{privateKeyDirectory: privateKeyFolder, publicKeyDirectory: publicKeyFolder,
		cache: cache, lock: &sync.RWMutex{}, encryptor: encryptor}
	// set callback on cache value removing

	return store, nil
}

func (store *KeyStore) generateKeyPair(filename string, clientID []byte) (*keys.Keypair, error) {
	keypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		return nil, err
	}
	if err := store.saveKeyPairWithFilename(keypair, filename, clientID); err != nil {
		return nil, err
	}
	return keypair, nil
}

func (store *KeyStore) saveKeyPairWithFilename(keypair *keys.Keypair, filename string, id []byte) error {
	privateKeysFolder := filepath.Dir(store.GetPrivateKeyFilePath(filename))
	err := os.MkdirAll(privateKeysFolder, 0700)
	if err != nil {
		return err
	}

	publicKeysFolder := filepath.Dir(store.getPublicKeyFilePath(filename))
	err = os.MkdirAll(publicKeysFolder, 0700)
	if err != nil {
		return err
	}

	encryptedPrivate, err := store.encryptor.Encrypt(keypair.Private.Value, id)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(store.GetPrivateKeyFilePath(filename), encryptedPrivate, PrivateFileMode)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(store.getPublicKeyFilePath(fmt.Sprintf("%s.pub", filename)), keypair.Public.Value, 0644)
	if err != nil {
		return err
	}
	store.cache.Add(filename, encryptedPrivate)
	return nil
}

func (store *KeyStore) generateKey(filename string, length uint8) ([]byte, error) {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		log.Error(err)
		return nil, err
	}
	dirpath := filepath.Dir(store.GetPrivateKeyFilePath(filename))
	err = os.MkdirAll(dirpath, 0700)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	err = ioutil.WriteFile(store.GetPrivateKeyFilePath(filename), randomBytes, PrivateFileMode)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return randomBytes, nil
}

// generateZoneKey for specific zone id. Will be generated new key pair and private key will be overwrited
func (store *KeyStore) generateZoneKey(id []byte) ([]byte, []byte, error) {
	/* save private key in fs, return id and public key*/
	keypair, err := store.generateKeyPair(getZoneKeyFilename(id), id)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	store.lock.Lock()
	defer store.lock.Unlock()
	encryptedKey, err := store.encryptor.Encrypt(keypair.Private.Value, id)
	if err != nil {
		return nil, nil, nil
	}
	utils.FillSlice(byte(0), keypair.Private.Value)
	// cache key
	store.cache.Add(getZoneKeyFilename(id), encryptedKey)
	return id, keypair.Public.Value, nil
}

// GenerateZoneKey generates zone ID and zone key pair, encrypts private key using zoneID as context,
// and saves encrypted PK in the filem returns zoneID and public key.
// Returns error if generation or encryption fail.
func (store *KeyStore) GenerateZoneKey() ([]byte, []byte, error) {
	var id []byte
	for {
		// generate until key not exists
		id = zone.GenerateZoneID()
		if !store.HasZonePrivateKey(id) {
			break
		}
	}
	return store.generateZoneKey(id)
}

// GetPrivateKeyFilePath return path for file with private key with configured folder for store
func (store *KeyStore) GetPrivateKeyFilePath(filename string) string {
	return fmt.Sprintf("%s%s%s", store.privateKeyDirectory, string(os.PathSeparator), filename)
}

func (store *KeyStore) getPublicKeyFilePath(filename string) string {
	return fmt.Sprintf("%s%s%s", store.publicKeyDirectory, string(os.PathSeparator), filename)
}

func (store *KeyStore) getPrivateKeyByFilename(id []byte, filename string) (*keys.PrivateKey, error) {
	if !keystore.ValidateID(id) {
		return nil, keystore.ErrInvalidClientID
	}
	store.lock.Lock()
	defer store.lock.Unlock()
	encryptedKey, ok := store.cache.Get(filename)
	if !ok {
		encryptedPrivateKey, err := utils.LoadPrivateKey(store.GetPrivateKeyFilePath(filename))
		if err != nil {
			return nil, err
		}
		encryptedKey = encryptedPrivateKey.Value
	}

	decryptedKey, err := store.encryptor.Decrypt(encryptedKey, id)
	if err != nil {
		return nil, err
	}
	log.Debugf("Load key from fs: %s", filename)
	store.cache.Add(filename, encryptedKey)
	return &keys.PrivateKey{Value: decryptedKey}, nil
}

// getPublicKeyByFilename return public key from cache or load from filesystem, store in cache and return
func (store *KeyStore) getPublicKeyByFilename(filename string) (*keys.PublicKey, error) {
	binKey, ok := store.cache.Get(filename)
	if !ok {
		publicKey, err := utils.LoadPublicKey(filename)
		if err != nil {
			return nil, err
		}
		store.cache.Add(filename, publicKey.Value)
		return publicKey, nil
	}
	return &keys.PublicKey{Value: binKey}, nil
}

// GetZonePublicKey return PublicKey by zoneID from cache or load from main store
func (store *KeyStore) GetZonePublicKey(zoneID []byte) (*keys.PublicKey, error) {
	fname := store.getPublicKeyFilePath(getZonePublicKeyFilename(zoneID))
	return store.getPublicKeyByFilename(fname)
}

// GetClientIDEncryptionPublicKey return PublicKey by clientID from cache or load from main store
func (store *KeyStore) GetClientIDEncryptionPublicKey(clientID []byte) (*keys.PublicKey, error) {
	fname := store.getPublicKeyFilePath(
		// use correct suffix for public keys
		getPublicKeyFilename(
			// use correct suffix as type of key
			[]byte(getServerDecryptionKeyFilename(clientID))))
	return store.getPublicKeyByFilename(fname)
}

// GetZonePrivateKey reads encrypted zone private key from fs, decrypts it with master key and zoneId
// and returns plaintext private key, or reading/decryption error.
func (store *KeyStore) GetZonePrivateKey(id []byte) (*keys.PrivateKey, error) {
	fname := getZoneKeyFilename(id)
	return store.getPrivateKeyByFilename(id, fname)
}

// HasZonePrivateKey returns if private key for this zoneID exists in cache or is written to fs.
func (store *KeyStore) HasZonePrivateKey(id []byte) bool {
	if !keystore.ValidateID(id) {
		return false
	}
	// add caching false answers. now if key doesn't exists than always checks on fs
	// it's system call and slow.
	if len(id) == 0 {
		return false
	}
	fname := getZoneKeyFilename(id)
	store.lock.RLock()
	defer store.lock.RUnlock()
	_, ok := store.cache.Get(fname)
	if ok {
		return true
	}
	exists, _ := utils.FileExists(store.GetPrivateKeyFilePath(fname))
	return exists
}

// GetPeerPublicKey returns public key for this clientID, gets it from cache or reads from fs.
func (store *KeyStore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	if !keystore.ValidateID(id) {
		return nil, keystore.ErrInvalidClientID
	}
	fname := getPublicKeyFilename(id)
	store.lock.Lock()
	defer store.lock.Unlock()
	key, ok := store.cache.Get(fname)
	if ok {
		log.Debugf("Load cached key: %s", fname)
		return &keys.PublicKey{Value: key}, nil
	}
	publicKey, err := utils.LoadPublicKey(store.getPublicKeyFilePath(fname))
	if err != nil {
		return nil, err
	}
	log.Debugf("Load key from fs: %s", fname)
	store.cache.Add(fname, publicKey.Value)
	return publicKey, nil
}

// GetPrivateKey reads encrypted client private key from fs, decrypts it with master key and clientID,
// and returns plaintext private key, or reading/decryption error.
func (store *KeyStore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	fname := getServerKeyFilename(id)
	return store.getPrivateKeyByFilename(id, fname)
}

// GetServerDecryptionPrivateKey reads encrypted server storage private key from fs,
// decrypts it with master key and clientID,
// and returns plaintext private key, or reading/decryption error.
func (store *KeyStore) GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error) {
	fname := getServerDecryptionKeyFilename(id)
	return store.getPrivateKeyByFilename(id, fname)
}

// GenerateConnectorKeys generates AcraConnector transport EC keypair using clientID as part of key name.
// Writes encrypted private key and plaintext public key to fs.
// Returns error if writing/encryption failed.
func (store *KeyStore) GenerateConnectorKeys(id []byte) error {
	if !keystore.ValidateID(id) {
		return keystore.ErrInvalidClientID
	}
	filename := getConnectorKeyFilename(id)

	_, err := store.generateKeyPair(filename, id)
	if err != nil {
		return err
	}
	return nil
}

// GenerateServerKeys generates AcraServer transport EC keypair using clientID as part of key name.
// Writes encrypted private key and plaintext public key to fs.
// Returns error if writing/encryption failed.
func (store *KeyStore) GenerateServerKeys(id []byte) error {
	if !keystore.ValidateID(id) {
		return keystore.ErrInvalidClientID
	}
	filename := getServerKeyFilename(id)
	_, err := store.generateKeyPair(filename, id)
	if err != nil {
		return err
	}
	return nil
}

// GenerateTranslatorKeys generates AcraTranslator transport EC keypair using clientID as part of key name.
// Writes encrypted private key and plaintext public key to fs.
// Returns error if writing/encryption failed.
func (store *KeyStore) GenerateTranslatorKeys(id []byte) error {
	if !keystore.ValidateID(id) {
		return keystore.ErrInvalidClientID
	}
	filename := getTranslatorKeyFilename(id)
	_, err := store.generateKeyPair(filename, id)
	if err != nil {
		return err
	}
	return nil
}

// GenerateDataEncryptionKeys generates Storage EC keypair for encrypting/decrypting data
// using clientID as part of key name.
// Writes encrypted private key and plaintext public key to fs.
// Returns error if writing/encryption failed.
func (store *KeyStore) GenerateDataEncryptionKeys(id []byte) error {
	if !keystore.ValidateID(id) {
		return keystore.ErrInvalidClientID
	}
	_, err := store.generateKeyPair(getServerDecryptionKeyFilename(id), id)
	if err != nil {
		return err
	}
	return nil
}

// Reset clears all cached keys
func (store *KeyStore) Reset() {
	store.cache.Clear()
}

// GetPoisonKeyPair generates EC keypair for encrypting/decrypting poison records, and writes it to fs
// encrypting private key or reads existing keypair from fs.
// Returns keypair or error if generation/decryption failed.
func (store *KeyStore) GetPoisonKeyPair() (*keys.Keypair, error) {
	privatePath := store.GetPrivateKeyFilePath(PoisonKeyFilename)
	publicPath := store.getPublicKeyFilePath(fmt.Sprintf("%s.pub", PoisonKeyFilename))
	privateExists, err := utils.FileExists(privatePath)
	if err != nil {
		return nil, err
	}
	publicExists, err := utils.FileExists(publicPath)
	if err != nil {
		return nil, err
	}
	if privateExists && publicExists {
		private, err := utils.LoadPrivateKey(privatePath)
		if err != nil {
			return nil, err
		}
		if private.Value, err = store.encryptor.Decrypt(private.Value, []byte(PoisonKeyFilename)); err != nil {
			return nil, err
		}
		public, err := utils.LoadPublicKey(publicPath)
		if err != nil {
			return nil, err
		}
		return &keys.Keypair{Public: public, Private: private}, nil
	}
	log.Infoln("Generate poison key pair")
	return store.generateKeyPair(PoisonKeyFilename, []byte(PoisonKeyFilename))
}

// GetAuthKey generates basic auth key for acraWebconfig, and writes it encrypted to fs,
// or reads existing key from fs.
// Returns key or error of generation/decryption failed.
func (store *KeyStore) GetAuthKey(remove bool) ([]byte, error) {
	keyPath := store.GetPrivateKeyFilePath(BasicAuthKeyFilename)
	keyExists, err := utils.FileExists(keyPath)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	if keyExists && !remove {
		key, err := utils.ReadFile(keyPath)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		return key, nil
	}
	log.Infof("Generate basic auth key for AcraWebconfig to %v", keyPath)
	return store.generateKey(BasicAuthKeyFilename, keystore.BasicAuthKeyLength)
}

// RotateZoneKey generate new key pair for ZoneId, overwrite private key with new and return new public key
func (store *KeyStore) RotateZoneKey(zoneID []byte) ([]byte, error) {
	_, public, err := store.generateZoneKey(zoneID)
	return public, err
}

// SaveZoneKeypair save or overwrite zone keypair
func (store *KeyStore) SaveZoneKeypair(id []byte, keypair *keys.Keypair) error {
	filename := getZoneKeyFilename(id)
	return store.saveKeyPairWithFilename(keypair, filename, id)
}

// SaveConnectorKeypair save or overwrite acra-connector keypair
func (store *KeyStore) SaveConnectorKeypair(id []byte, keypair *keys.Keypair) error {
	filename := getConnectorKeyFilename(id)
	return store.saveKeyPairWithFilename(keypair, filename, id)
}

// SaveServerKeypair save or overwrite acra-server keypair
func (store *KeyStore) SaveServerKeypair(id []byte, keypair *keys.Keypair) error {
	filename := getServerKeyFilename(id)
	return store.saveKeyPairWithFilename(keypair, filename, id)
}

// SaveTranslatorKeypair save or overwrite acra-translator keypair
func (store *KeyStore) SaveTranslatorKeypair(id []byte, keypair *keys.Keypair) error {
	filename := getTranslatorKeyFilename(id)
	return store.saveKeyPairWithFilename(keypair, filename, id)
}

// SaveDataEncryptionKeys save or overwrite decryption keypair for client id
func (store *KeyStore) SaveDataEncryptionKeys(id []byte, keypair *keys.Keypair) error {
	filename := getServerDecryptionKeyFilename(id)
	return store.saveKeyPairWithFilename(keypair, filename, id)
}

// Add value to inner cache
func (store *KeyStore) Add(keyID string, keyValue []byte) {
	store.cache.Add(keyID, keyValue)
}

// Get value from inner cache
func (store *KeyStore) Get(keyID string) ([]byte, bool) {
	return store.cache.Get(keyID)
}
