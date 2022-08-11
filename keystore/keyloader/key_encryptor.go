package keyloader

import (
	"errors"
	"sync"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	log "github.com/sirupsen/logrus"
)

var (
	// ErrKeyEncryptorFabricNotFound represent an error of missing KeyEncryptorFabric in registry
	ErrKeyEncryptorFabricNotFound = errors.New("KeyEncryptorFabric not found by strategy")
	lock                          = sync.Mutex{}
)

// KeyEncryptorFabric represent Fabric interface for constructing keystore.KeyEncryptor for v1 keystore and crypto.KeyStoreSuite for v2
type KeyEncryptorFabric interface {
	NewKeyEncryptor() (keystore.KeyEncryptor, error)
	NewKeyEncryptorSuite() (*crypto.KeyStoreSuite, error)
}

var keyEncryptorFabrics = map[string]KeyEncryptorFabric{}

// RegisterKeyEncryptorFabric add new kms MasterKeyLoader to registry
func RegisterKeyEncryptorFabric(strategy string, keyEncryptorFabric KeyEncryptorFabric) {
	lock.Lock()
	keyEncryptorFabrics[strategy] = keyEncryptorFabric
	lock.Unlock()
	log.WithField("strategy", strategy).Debug("Registered KeyEncryptorFabric")
}

// MasterKeyLoader interface for loading ACRA_MASTER_KEYs from different sources.
type MasterKeyLoader interface {
	LoadMasterKey() (key []byte, err error)
	LoadMasterKeys() (encryption []byte, signature []byte, err error)
}

// CreateKeyEncryptor returns initialized keystore.KeyEncryptor interface depending on incoming keystoreStrategy
func CreateKeyEncryptor(keystoreStrategy string) (keystore.KeyEncryptor, error) {
	keyEncryptorFabric, ok := keyEncryptorFabrics[keystoreStrategy]
	if !ok {
		log.WithField("strategy", keystoreStrategy).WithField("supported", SupportedKeystoreStrategies).
			Warnf("KeyEncryptorFabric not found")
		return nil, ErrKeyEncryptorFabricNotFound
	}
	return keyEncryptorFabric.NewKeyEncryptor()
}

// CreateKeyEncryptorSuite returns initialized crypto.KeyStoreSuite interface depending on incoming keystoreStrategy
func CreateKeyEncryptorSuite(keystoreStrategy string) (*crypto.KeyStoreSuite, error) {
	keyEncryptorFabric, ok := keyEncryptorFabrics[keystoreStrategy]
	if !ok {
		log.WithField("strategy", keystoreStrategy).WithField("supported", SupportedKeystoreStrategies).
			Warnf("KeyEncryptorFabric not found")
		return nil, ErrKeyEncryptorFabricNotFound
	}
	return keyEncryptorFabric.NewKeyEncryptorSuite()
}
