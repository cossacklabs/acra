package keystore

import (
	"github.com/cossacklabs/themis/gothemis/keys"
	"io/ioutil"
	"path/filepath"
)

type ConnectorFileSystemKeyStore struct {
	directory string
	clientId  []byte
	encryptor KeyEncryptor
}

func NewConnectorFileSystemKeyStore(directory string, clientId []byte, encryptor KeyEncryptor) (*ConnectorFileSystemKeyStore, error) {
	return &ConnectorFileSystemKeyStore{directory: directory, clientId: clientId, encryptor: encryptor}, nil
}

func (store *ConnectorFileSystemKeyStore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(filepath.Join(store.directory, getConnectorKeyFilename(id)))
	if err != nil {
		return nil, err
	}
	if privateKey, err := store.encryptor.Decrypt(keyData, id); err != nil {
		return nil, err
	} else {
		return &keys.PrivateKey{Value: privateKey}, nil
	}
}

func (store *ConnectorFileSystemKeyStore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	key, err := ioutil.ReadFile(filepath.Join(store.directory, getPublicKeyFilename([]byte(getServerKeyFilename(store.clientId)))))
	if err != nil {
		return nil, err
	}
	return &keys.PublicKey{Value: key}, nil
}
