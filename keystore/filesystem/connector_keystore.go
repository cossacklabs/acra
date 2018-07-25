package filesystem

import (
	"errors"
	"github.com/cossacklabs/acra/cmd/acra-connector/connector-mode"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io/ioutil"
	"path/filepath"
)

type ConnectorFileSystemKeyStore struct {
	directory     string
	clientID      []byte
	encryptor     keystore.KeyEncryptor
	connectorMode connector_mode.ConnectorMode
}

func NewConnectorFileSystemKeyStore(directory string, clientID []byte, encryptor keystore.KeyEncryptor, mode connector_mode.ConnectorMode) (*ConnectorFileSystemKeyStore, error) {
	return &ConnectorFileSystemKeyStore{directory: directory, clientID: clientID, encryptor: encryptor, connectorMode: mode}, nil
}

func (store *ConnectorFileSystemKeyStore) CheckIfPrivateKeyExists(id []byte) (bool, error) {
	_, err := ioutil.ReadFile(filepath.Join(store.directory, getConnectorKeyFilename(id)))
	if err != nil {
		return false, err
	}
	return true, nil
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
	filename := ""
	switch store.connectorMode {
	case connector_mode.AcraServerMode:
		filename = getServerKeyFilename(store.clientID)
	case connector_mode.AcraTranslatorMode:
		filename = getTranslatorKeyFilename(store.clientID)
	default:
		return nil, errors.New("Unsupported ConnectorMode, can't find PeerPublicKey")
	}

	key, err := ioutil.ReadFile(filepath.Join(store.directory, getPublicKeyFilename([]byte(filename))))
	if err != nil {
		return nil, err
	}
	return &keys.PublicKey{Value: key}, nil
}
