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
	"path/filepath"

	connector_mode "github.com/cossacklabs/acra/cmd/acra-connector/connector-mode"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/themis/gothemis/keys"

	"github.com/prometheus/common/log"
)

// ConnectorFileSystemKeyStore stores AcraConnector keys configuration
type ConnectorFileSystemKeyStore struct {
	storageKeyStore *KeyStore

	directory     string
	clientID      []byte
	storage       Storage
	encryptor     keystore.KeyEncryptor
	connectorMode connector_mode.ConnectorMode
}

// ConnectorFileSystemKeyStoreBuilder allows to build a custom keystore.
type ConnectorFileSystemKeyStoreBuilder struct {
	directory     string
	clientID      []byte
	storage       Storage
	encryptor     keystore.KeyEncryptor
	connectorMode connector_mode.ConnectorMode
}

// NewCustomConnectorFileSystemKeyStore allows to customize a translator keystore.
func NewCustomConnectorFileSystemKeyStore() *ConnectorFileSystemKeyStoreBuilder {
	return &ConnectorFileSystemKeyStoreBuilder{
		storage: &DummyStorage{},
	}
}

var (
	errNoClientID      = errors.New("client ID not specified")
	errNoConnectorMode = errors.New("connector mode not specified")
)

// KeyDirectory sets key directory.
func (b *ConnectorFileSystemKeyStoreBuilder) KeyDirectory(directory string) *ConnectorFileSystemKeyStoreBuilder {
	b.directory = directory
	return b
}

// ClientID sets key client ID.
func (b *ConnectorFileSystemKeyStoreBuilder) ClientID(clientID []byte) *ConnectorFileSystemKeyStoreBuilder {
	b.clientID = clientID
	return b
}

// Storage sets custom storage.
func (b *ConnectorFileSystemKeyStoreBuilder) Storage(storage Storage) *ConnectorFileSystemKeyStoreBuilder {
	b.storage = storage
	return b
}

// Encryptor sets encryptor.
func (b *ConnectorFileSystemKeyStoreBuilder) Encryptor(encryptor keystore.KeyEncryptor) *ConnectorFileSystemKeyStoreBuilder {
	b.encryptor = encryptor
	return b
}

// ConnectorMode sets connector mode.
func (b *ConnectorFileSystemKeyStoreBuilder) ConnectorMode(connectorMode connector_mode.ConnectorMode) *ConnectorFileSystemKeyStoreBuilder {
	b.connectorMode = connectorMode
	return b
}

// Build a keystore.
func (b *ConnectorFileSystemKeyStoreBuilder) Build() (*ConnectorFileSystemKeyStore, error) {
	if b.directory == "" {
		return nil, errNoPrivateKeyDir
	}
	if b.clientID == nil {
		return nil, errNoClientID
	}
	if b.encryptor == nil {
		return nil, errNoEncryptor
	}
	if b.connectorMode == "" {
		return nil, errNoConnectorMode
	}

	// Build storage KeyStore
	storageKeyStore, err := NewCustomFilesystemKeyStore().
		KeyDirectory(b.directory).
		Storage(b.storage).
		Encryptor(b.encryptor).
		Build()

	if err != nil {
		return nil, err
	}

	return &ConnectorFileSystemKeyStore{
		directory:       b.directory,
		clientID:        b.clientID,
		storage:         b.storage,
		encryptor:       b.encryptor,
		connectorMode:   b.connectorMode,
		storageKeyStore: storageKeyStore,
	}, nil
}

// NewConnectorFileSystemKeyStore creates new ConnectorFileSystemKeyStore
func NewConnectorFileSystemKeyStore(directory string, clientID []byte, encryptor keystore.KeyEncryptor, mode connector_mode.ConnectorMode) (*ConnectorFileSystemKeyStore, error) {
	return &ConnectorFileSystemKeyStore{directory: directory, clientID: clientID, storage: &fileStorage{}, encryptor: encryptor, connectorMode: mode}, nil
}

// CheckIfPrivateKeyExists checks if Keystore has Connector transport private key for establishing Secure Session connection,
// returns true if key exists in fs.
func (store *ConnectorFileSystemKeyStore) CheckIfPrivateKeyExists(id []byte) (bool, error) {
	return store.storage.Exists(filepath.Join(store.directory, getConnectorKeyFilename(id)))
}

// GetPrivateKey reads and decrypts Connector transport private key for establishing Secure Session connection.
func (store *ConnectorFileSystemKeyStore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	keyData, err := store.storage.ReadFile(filepath.Join(store.directory, getConnectorKeyFilename(id)))
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

	key, err := store.storage.ReadFile(filepath.Join(store.directory, getPublicKeyFilename([]byte(filename))))
	if err != nil {
		return nil, err
	}
	return &keys.PublicKey{Value: key}, nil
}

// GetLogSecretKey return key for log integrity checks
func (store *ConnectorFileSystemKeyStore) GetLogSecretKey() ([]byte, error) {
	filename := getLogKeyFilename()
	var err error
	encryptedKey, ok := store.storageKeyStore.Get(filename)
	if !ok {
		encryptedKey, err = store.storageKeyStore.ReadKeyFile(store.storageKeyStore.GetPrivateKeyFilePath(filename))
		if err != nil {
			return nil, err
		}
	}
	decryptedKey, err := store.encryptor.Decrypt(encryptedKey, []byte(SecureLogKeyFilename))
	if err != nil {
		return nil, err
	}
	log.Debugf("Load key from fs: %s", filename)
	store.storageKeyStore.Add(filename, encryptedKey)
	return decryptedKey, nil
}
