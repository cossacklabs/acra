package keystore

import (
	"errors"
	"fmt"
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

type FilesystemKeyStore struct {
	keys                map[string][]byte
	privateKeyDirectory string
	publicKeyDirectory  string
	lock                *sync.RWMutex
}

func NewFilesystemKeyStore(directory string) (*FilesystemKeyStore, error) {
	return NewFilesystemKeyStoreTwoPath(directory, directory)
}

func NewFilesystemKeyStoreTwoPath(privateKeyFolder, publicKeyFolder string) (*FilesystemKeyStore, error) {
	// check folder for private key
	directory, err := utils.AbsPath(privateKeyFolder)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(directory)
	if nil == err && runtime.GOOS == "linux" && fi.Mode().Perm().String() != "-rwx------" {
		log.Errorln(" key store folder has an incorrect permissions")
		return nil, errors.New("key store folder has an incorrect permissions")
	}
	if privateKeyFolder != publicKeyFolder {
		// check folder for public key
		directory, err = utils.AbsPath(privateKeyFolder)
		if err != nil {
			return nil, err
		}
		fi, err = os.Stat(directory)
		if nil != err && !os.IsNotExist(err) {
			return nil, err
		}
	}
	return &FilesystemKeyStore{privateKeyDirectory: privateKeyFolder, publicKeyDirectory: publicKeyFolder,
		keys: make(map[string][]byte), lock: &sync.RWMutex{}}, nil
}

func (store *FilesystemKeyStore) generateKeyPair(filename string) (*keys.Keypair, error) {
	keypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		return nil, err
	}
	dirpath := filepath.Dir(store.getPrivateKeyFilePath(filename))
	err = os.MkdirAll(dirpath, 0700)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(store.getPrivateKeyFilePath(filename), keypair.Private.Value, 0600)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(store.getPublicKeyFilePath(fmt.Sprintf("%s.pub", filename)), keypair.Public.Value, 0644)
	if err != nil {
		return nil, err
	}
	return keypair, nil
}

func (store *FilesystemKeyStore) GenerateZoneKey() ([]byte, []byte, error) {
	/* save private key in fs, return id and public key*/
	var id []byte
	for {
		// generate until key not exists
		id = zone.GenerateZoneId()
		if !store.HasZonePrivateKey(id) {
			break
		}
	}

	keypair, err := store.generateKeyPair(getZoneKeyFilename(id))
	if err != nil {
		return []byte{}, []byte{}, err
	}
	store.lock.Lock()
	defer store.lock.Unlock()
	// cache key
	store.keys[getZoneKeyFilename(id)] = keypair.Private.Value
	return id, keypair.Public.Value, nil
}

func (store *FilesystemKeyStore) getPrivateKeyFilePath(filename string) string {
	return fmt.Sprintf("%s%s%s", store.privateKeyDirectory, string(os.PathSeparator), filename)
}

func (store *FilesystemKeyStore) getPublicKeyFilePath(filename string) string {
	return fmt.Sprintf("%s%s%s", store.publicKeyDirectory, string(os.PathSeparator), filename)
}

func (store *FilesystemKeyStore) GetZonePrivateKey(id []byte) (*keys.PrivateKey, error) {
	if !ValidateId(id) {
		return nil, ErrInvalidClientId
	}
	fname := getZoneKeyFilename(id)
	store.lock.Lock()
	defer store.lock.Unlock()
	key, ok := store.keys[fname]
	if ok {
		log.Debugf("load cached key: %s", fname)
		return &keys.PrivateKey{Value: key}, nil
	}
	privateKey, err := utils.LoadPrivateKey(store.getPrivateKeyFilePath(fname))
	if err != nil {
		return nil, err
	}
	log.Debugf("load key from fs: %s", fname)
	store.keys[fname] = privateKey.Value
	return privateKey, nil
}

func (store *FilesystemKeyStore) HasZonePrivateKey(id []byte) bool {
	if !ValidateId(id) {
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
	_, ok := store.keys[fname]
	if ok {
		return true
	}
	exists, _ := utils.FileExists(store.getPrivateKeyFilePath(fname))
	return exists
}

func (store *FilesystemKeyStore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	if !ValidateId(id) {
		return nil, ErrInvalidClientId
	}
	fname := getPublicKeyFilename(id)
	store.lock.Lock()
	defer store.lock.Unlock()
	key, ok := store.keys[fname]
	if ok {
		log.Debugf("load cached key: %s", fname)
		return &keys.PublicKey{Value: key}, nil
	}
	publicKey, err := utils.LoadPublicKey(store.getPublicKeyFilePath(fname))
	if err != nil {
		return nil, err
	}
	log.Debugf("load key from fs: %s", fname)
	store.keys[fname] = publicKey.Value
	return publicKey, nil
}

func (store *FilesystemKeyStore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	if !ValidateId(id) {
		return nil, ErrInvalidClientId
	}
	fname := getServerKeyFilename(id)
	lock.Lock()
	defer lock.Unlock()
	key, ok := store.keys[fname]
	if ok {
		log.Debugf("load cached key: %s", fname)
		return &keys.PrivateKey{Value: key}, nil
	}
	privateKey, err := utils.LoadPrivateKey(store.getPrivateKeyFilePath(fname))
	if err != nil {
		return nil, err
	}
	log.Debugf("load key from fs: %s", fname)
	store.keys[fname] = privateKey.Value
	return privateKey, nil
}

func (store *FilesystemKeyStore) GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error) {
	if !ValidateId(id) {
		return nil, ErrInvalidClientId
	}
	fname := getServerDecryptionKeyFilename(id)
	store.lock.Lock()
	defer store.lock.Unlock()
	key, ok := store.keys[fname]
	if ok {
		log.Debugf("load cached key: %s", fname)
		return &keys.PrivateKey{Value: key}, nil
	}
	privateKey, err := utils.LoadPrivateKey(store.getPrivateKeyFilePath(fname))
	if err != nil {
		return nil, err
	}
	log.Debugf("load key from fs: %s", fname)
	store.keys[fname] = privateKey.Value
	return privateKey, nil
}

func (store *FilesystemKeyStore) GenerateProxyKeys(id []byte) error {
	if !ValidateId(id) {
		return ErrInvalidClientId
	}
	filename := getProxyKeyFilename(id)
	_, err := store.generateKeyPair(filename)
	return err
}
func (store *FilesystemKeyStore) GenerateServerKeys(id []byte) error {
	if !ValidateId(id) {
		return ErrInvalidClientId
	}
	filename := getServerKeyFilename(id)
	_, err := store.generateKeyPair(filename)
	return err
}

// generate key pair for data encryption/decryption
func (store *FilesystemKeyStore) GenerateDataEncryptionKeys(id []byte) error {
	if !ValidateId(id) {
		return ErrInvalidClientId
	}
	_, err := store.generateKeyPair(getServerDecryptionKeyFilename(id))
	return err
}

// clear all cached keys
func (store *FilesystemKeyStore) Reset() {
	store.keys = make(map[string][]byte)
}

func (store *FilesystemKeyStore) GetPoisonKeyPair() (*keys.Keypair, error) {
	privatePath := store.getPrivateKeyFilePath(POISON_KEY_FILENAME)
	publicPath := store.getPublicKeyFilePath(fmt.Sprintf("%s.pub", POISON_KEY_FILENAME))
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
		public, err := utils.LoadPublicKey(publicPath)
		if err != nil {
			return nil, err
		}
		return &keys.Keypair{Public: public, Private: private}, nil
	}
	log.Infoln("Generate poison key pair")
	return store.generateKeyPair(POISON_KEY_FILENAME)
}
