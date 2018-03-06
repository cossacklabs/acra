package keystore

import (
	"github.com/cossacklabs/themis/gothemis/keys"
	"io/ioutil"
	"path/filepath"
)

type ProxyFileSystemKeyStore struct {
	directory string
	clientId  []byte
}

func NewProxyFileSystemKeyStore(directory string, clientId []byte) (*ProxyFileSystemKeyStore, error) {
	return &ProxyFileSystemKeyStore{directory: directory, clientId: clientId}, nil
}

func (store *ProxyFileSystemKeyStore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(filepath.Join(store.directory, getProxyKeyFilename(id)))
	if err != nil {
		return nil, err
	}
	return &keys.PrivateKey{Value: keyData}, nil
}

func (store *ProxyFileSystemKeyStore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	key, err := ioutil.ReadFile(filepath.Join(store.directory, getPublicKeyFilename([]byte(getServerKeyFilename(store.clientId)))))
	if err != nil {
		return nil, err
	}
	return &keys.PublicKey{Value: key}, nil
}
