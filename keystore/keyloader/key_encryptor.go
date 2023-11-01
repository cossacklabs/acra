package keyloader

import (
	"errors"
	"flag"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd/args"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/kms/base"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
)

var (
	// ErrKeyEncryptorFabricNotFound represent an error of missing KeyEncryptorFabric in registry
	ErrKeyEncryptorFabricNotFound = errors.New("KeyEncryptorFabric not found by strategy")
	lock                          = sync.Mutex{}
)

var keyEncryptorFabrics = map[string]KeyEncryptorFabric{}

// KeyEncryptorFabric represent Fabric interface for constructing keystore.KeyEncryptor for v1 keystore and crypto.KeyStoreSuite for v2
type KeyEncryptorFabric interface {
	RegisterCLIParameters(flags *flag.FlagSet, prefix, description string)
	NewKeyEncryptor(extractor *args.ServiceExtractor, prefix string) (keystore.KeyEncryptor, error)
	NewKeyEncryptorSuite(extractor *args.ServiceExtractor, prefix string) (*crypto.KeyStoreSuite, error)
	GetKeyMapper() base.KeyMapper
}

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
func CreateKeyEncryptor(extractor *args.ServiceExtractor, prefix string) (keystore.KeyEncryptor, error) {
	cliOptions := ParseCLIOptionsFromFlags(extractor, prefix)

	keyEncryptorFabric, ok := keyEncryptorFabrics[cliOptions.KeystoreEncryptorType]
	if !ok {
		log.WithField("strategy", cliOptions.KeystoreEncryptorType).WithField("supported", SupportedKeystoreStrategies).
			Warnf("KeyEncryptorFabric not found")
		return nil, ErrKeyEncryptorFabricNotFound
	}

	return keyEncryptorFabric.NewKeyEncryptor(extractor, prefix)
}

// CreateKeyEncryptorSuite returns initialized crypto.KeyStoreSuite interface depending on incoming keystoreStrategy
func CreateKeyEncryptorSuite(extractor *args.ServiceExtractor, prefix string) (*crypto.KeyStoreSuite, error) {
	cliOptions := ParseCLIOptionsFromFlags(extractor, prefix)

	keyEncryptorFabric, ok := keyEncryptorFabrics[cliOptions.KeystoreEncryptorType]
	if !ok {
		log.WithField("strategy", cliOptions.KeystoreEncryptorType).WithField("supported", SupportedKeystoreStrategies).
			Warnf("KeyEncryptorFabric not found")
		return nil, ErrKeyEncryptorFabricNotFound
	}
	return keyEncryptorFabric.NewKeyEncryptorSuite(extractor, prefix)
}

// RegisterKeyStoreStrategyParameters register flags for all fabrics with CommandLine flags
func RegisterKeyStoreStrategyParameters() {
	RegisterKeyStoreStrategyParametersWithFlags(flag.CommandLine, "", "")
}

// RegisterKeyStoreStrategyParametersWithFlags register flags for all fabrics
func RegisterKeyStoreStrategyParametersWithFlags(flag *flag.FlagSet, prefix, description string) {
	RegisterCLIParametersWithFlagSet(flag, prefix, description)

	for _, v := range keyEncryptorFabrics {
		v.RegisterCLIParameters(flag, prefix, description)
	}
}
