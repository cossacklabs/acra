package filesystem

import (
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io/ioutil"
	"path/filepath"
)

// TranslatorFileSystemKeyStore stores AcraTranslator keys configuration
type TranslatorFileSystemKeyStore struct {
	*FilesystemKeyStore
	directory string
	encryptor keystore.KeyEncryptor
}

// NewTranslatorFileSystemKeyStore creates new TranslatorFileSystemKeyStore
func NewTranslatorFileSystemKeyStore(directory string, encryptor keystore.KeyEncryptor, cacheSize int) (*TranslatorFileSystemKeyStore, error) {
	fsKeystore, err := NewFileSystemKeyStoreWithCacheSize(directory, encryptor, cacheSize)
	if err != nil {
		return nil, err
	}
	return &TranslatorFileSystemKeyStore{FilesystemKeyStore: fsKeystore, directory: directory, encryptor: encryptor}, nil
}

// CheckIfPrivateKeyExists checks if Keystore has Translator transport private key for establishing Secure Session connection,
// returns true if key exists in fs.
func (store *TranslatorFileSystemKeyStore) CheckIfPrivateKeyExists(id []byte) (bool, error) {
	_, err := ioutil.ReadFile(filepath.Join(store.directory, getTranslatorKeyFilename(id)))
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetPrivateKey reads and decrypts Translator transport private key for establishing Secure Session connection.
func (store *TranslatorFileSystemKeyStore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(filepath.Join(store.directory, getTranslatorKeyFilename(id)))
	if err != nil {
		return nil, err
	}

	var privateKey []byte
	if privateKey, err = store.encryptor.Decrypt(keyData, id); err != nil {
		return nil, err
	}
	return &keys.PrivateKey{Value: privateKey}, nil
}

// GetPeerPublicKey returns other party transport public key.
func (store *TranslatorFileSystemKeyStore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	filename := getConnectorKeyFilename(id)
	key, err := ioutil.ReadFile(filepath.Join(store.directory, getPublicKeyFilename([]byte(filename))))
	if err != nil {
		return nil, err
	}
	return &keys.PublicKey{Value: key}, nil
}
