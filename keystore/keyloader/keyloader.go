package keyloader

import (
	"errors"
	"sync"

	log "github.com/sirupsen/logrus"
)

// ErrMasterKeyLoaderCreatorNotFound represent an error of missing MasterKeyLoaderCreator
var ErrMasterKeyLoaderCreatorNotFound = errors.New("MasterKeyLoaderCreator not found by strategy")

var lock = sync.Mutex{}
var keyLoaderStrategies = map[string]MasterKeyLoaderCreator{}

// MasterKeyLoaderCreator generic function for creating MasterKeyLoader
type MasterKeyLoaderCreator func() (MasterKeyLoader, error)

// RegisterKeyLoaderCreator add new kms MasterKeyLoader to registry
func RegisterKeyLoaderCreator(strategy string, creator MasterKeyLoaderCreator) {
	lock.Lock()
	keyLoaderStrategies[strategy] = creator
	lock.Unlock()
	log.WithField("strategy", strategy).Debug("Registered MasterKeyLoaderCreator")
}

// MasterKeyLoader interface for loading ACRA_MASTER_KEYs from different sources.
type MasterKeyLoader interface {
	LoadMasterKey() (key []byte, err error)
	LoadMasterKeys() (encryption []byte, signature []byte, err error)
}

// GetInitializedMasterKeyLoader returns initialized MasterKeyLoader interface depending on incoming load key strategy
// with predefined ACRA_MASTER_KEY env name
func GetInitializedMasterKeyLoader(keystoreStrategy string) (MasterKeyLoader, error) {
	createMasterKeyLoader, ok := keyLoaderStrategies[keystoreStrategy]
	if !ok {
		log.WithField("strategy", keystoreStrategy).WithField("supported", SupportedKeystoreStrategies).
			Warnf("MasterKeyLoaderCreator not found")
		return nil, ErrMasterKeyLoaderCreatorNotFound
	}
	return createMasterKeyLoader()
}
