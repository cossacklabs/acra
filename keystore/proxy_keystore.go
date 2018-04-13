package keystore

import (
	"github.com/cossacklabs/themis/gothemis/keys"
	"io/ioutil"
	"path/filepath"
)

type ProxyFileSystemKeyStore struct {
	directory string
	clientId  []byte
	encryptor KeyEncryptor
}

func NewProxyFileSystemKeyStore(directory string, clientId []byte, encryptor KeyEncryptor) (*ProxyFileSystemKeyStore, error) {
	return &ProxyFileSystemKeyStore{directory: directory, clientId: clientId, encryptor: encryptor}, nil
}

func (store *ProxyFileSystemKeyStore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(filepath.Join(store.directory, getProxyKeyFilename(id)))
	if err != nil {
		return nil, err
	}
	if privateKey, err := store.encryptor.Decrypt(keyData, id); err != nil {
		return nil, err
	} else {
		return &keys.PrivateKey{Value: privateKey}, nil
	}
}

func (store *ProxyFileSystemKeyStore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	key, err := ioutil.ReadFile(filepath.Join(store.directory, getPublicKeyFilename([]byte(getServerKeyFilename(store.clientId)))))
	if err != nil {
		return nil, err
	}
	return &keys.PublicKey{Value: key}, nil
}
