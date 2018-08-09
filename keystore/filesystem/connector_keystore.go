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
	"errors"
	"github.com/cossacklabs/acra/cmd/acra-connector/connector-mode"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io/ioutil"
	"path/filepath"
)

// ConnectorFileSystemKeyStore stores AcraConnector keys configuration
type ConnectorFileSystemKeyStore struct {
	directory     string
	clientID      []byte
	encryptor     keystore.KeyEncryptor
	connectorMode connector_mode.ConnectorMode
}

// NewConnectorFileSystemKeyStore creates new ConnectorFileSystemKeyStore
func NewConnectorFileSystemKeyStore(directory string, clientID []byte, encryptor keystore.KeyEncryptor, mode connector_mode.ConnectorMode) (*ConnectorFileSystemKeyStore, error) {
	return &ConnectorFileSystemKeyStore{directory: directory, clientID: clientID, encryptor: encryptor, connectorMode: mode}, nil
}

// CheckIfPrivateKeyExists checks if Keystore has Connector transport private key for establishing Secure Session connection,
// returns true if key exists in fs.
func (store *ConnectorFileSystemKeyStore) CheckIfPrivateKeyExists(id []byte) (bool, error) {
	_, err := ioutil.ReadFile(filepath.Join(store.directory, getConnectorKeyFilename(id)))
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetPrivateKey reads and decrypts Connector transport private key for establishing Secure Session connection.
func (store *ConnectorFileSystemKeyStore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(filepath.Join(store.directory, getConnectorKeyFilename(id)))
	if err != nil {
		return nil, err
	}

	var privateKey []byte
	if privateKey, err = store.encryptor.Decrypt(keyData, id); err != nil {
		return nil, err
	}
	return &keys.PrivateKey{Value: privateKey}, nil
}

// GetPeerPublicKey returns other party transport public key depending on AcraConnector mode:
// returns AcraServer transport public key for AcraServerMode, and
// returns  AcraTranslator transport public key for AcraTranslatorMode.
func (store *ConnectorFileSystemKeyStore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	filename := ""
	switch store.connectorMode {
	case connector_mode.AcraServerMode:
		filename = getServerKeyFilename(store.clientID)
	case connector_mode.AcraTranslatorMode:
		filename = getTranslatorKeyFilename(store.clientID)
	default:
		return nil, errors.New("unsupported ConnectorMode, can't find PeerPublicKey")
	}

	key, err := ioutil.ReadFile(filepath.Join(store.directory, getPublicKeyFilename([]byte(filename))))
	if err != nil {
		return nil, err
	}
	return &keys.PublicKey{Value: key}, nil
}
