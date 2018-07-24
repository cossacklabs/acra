package filesystem

import (
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io/ioutil"
	"path/filepath"
)

type TranslatorFileSystemKeyStore struct {
	*FilesystemKeyStore
	directory string
	encryptor keystore.KeyEncryptor
}

func NewTranslatorFileSystemKeyStore(directory string, encryptor keystore.KeyEncryptor, cacheSize int) (*TranslatorFileSystemKeyStore, error) {
	fsKeystore, err := NewFileSystemKeyStoreWithCacheSize(directory, encryptor, cacheSize)
	if err != nil {
		return nil, err
	}
	return &TranslatorFileSystemKeyStore{FilesystemKeyStore: fsKeystore, directory: directory, encryptor: encryptor}, nil
}

func (store *TranslatorFileSystemKeyStore) CheckIfPrivateKeyExists(id []byte) (bool, error) {
	_, err := ioutil.ReadFile(filepath.Join(store.directory, getTranslatorKeyFilename(id)))
	if err != nil {
		return false, err
	}
	return true, nil
}

func (store *TranslatorFileSystemKeyStore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(filepath.Join(store.directory, getTranslatorKeyFilename(id)))
	if err != nil {
		return nil, err
	}
	if privateKey, err := store.encryptor.Decrypt(keyData, id); err != nil {
		return nil, err
	} else {
		return &keys.PrivateKey{Value: privateKey}, nil
	}
}

func (store *TranslatorFileSystemKeyStore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	filename := getConnectorKeyFilename(id)
	key, err := ioutil.ReadFile(filepath.Join(store.directory, getPublicKeyFilename([]byte(filename))))
	if err != nil {
		return nil, err
	}
	return &keys.PublicKey{Value: key}, nil
}
