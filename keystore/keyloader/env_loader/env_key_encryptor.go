package env_loader

import (
	"flag"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd/args"
	"github.com/cossacklabs/acra/keystore"
	baseKMS "github.com/cossacklabs/acra/keystore/kms/base"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
)

// EnvKeyEncryptorFabric implementation of keyloader.KeyEncryptorFabric for `env_master_key` strategy
type EnvKeyEncryptorFabric struct {
	envName string
}

// NewEnvKeyEncryptorFabric create new KeyEncryptorFabric
func NewEnvKeyEncryptorFabric(envName string) EnvKeyEncryptorFabric {
	return EnvKeyEncryptorFabric{
		envName,
	}
}

// NewKeyEncryptor fabric of keystore.KeyEncryptor for `env_master_key` strategy
func (k EnvKeyEncryptorFabric) NewKeyEncryptor(extractor *args.ServiceExtractor, prefix string) (keystore.KeyEncryptor, error) {
	loader := NewEnvLoader(k.envName)

	key, err := loader.LoadMasterKey()
	if err != nil {
		return nil, err
	}
	return keystore.NewSCellKeyEncryptor(key)
}

// NewKeyEncryptorSuite fabric of crypto.KeyStoreSuite for `env_master_key` strategy
func (k EnvKeyEncryptorFabric) NewKeyEncryptorSuite(extractor *args.ServiceExtractor, prefix string) (*crypto.KeyStoreSuite, error) {
	loader := NewEnvLoader(k.envName)

	encryption, signature, err := loader.LoadMasterKeys()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master key")
		return nil, err
	}
	return keystoreV2.NewSCellSuite(encryption, signature)
}

// RegisterCLIParameters empty implementation of KeyEncryptorFabric interface
func (k EnvKeyEncryptorFabric) RegisterCLIParameters(flags *flag.FlagSet, prefix, description string) {
	// no flag registration for EnvKeyEncryptorFabric
}

// GetKeyMapper return KeyMapper for `env_master_key` strategy
func (k EnvKeyEncryptorFabric) GetKeyMapper() baseKMS.KeyMapper {
	panic("No KeyMapper for env_master_key strategy")
}
