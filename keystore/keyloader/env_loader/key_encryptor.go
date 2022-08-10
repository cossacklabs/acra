package env_loader

import (
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/keyloader"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	log "github.com/sirupsen/logrus"
)

// KeyEncryptorFabric implementation of keyloader.KeyEncryptorFabric for `env_master_key` strategy
type KeyEncryptorFabric struct {
	envName string
}

// NewKeyEncryptorFabric create new KeyEncryptorFabric
func NewKeyEncryptorFabric(envName string) keyloader.KeyEncryptorFabric {
	return KeyEncryptorFabric{
		envName,
	}
}

// NewKeyEncryptor fabric of keystore.KeyEncryptor for `env_master_key` strategy
func (k KeyEncryptorFabric) NewKeyEncryptor() (keystore.KeyEncryptor, error) {
	loader := NewEnvLoader(k.envName)

	key, err := loader.LoadMasterKey()
	if err != nil {
		return nil, err
	}
	return keystore.NewSCellKeyEncryptor(key)
}

// NewKeyEncryptorSuite fabric of crypto.KeyStoreSuite for `env_master_key` strategy
func (k KeyEncryptorFabric) NewKeyEncryptorSuite() (*crypto.KeyStoreSuite, error) {
	loader := NewEnvLoader(k.envName)

	encryption, signature, err := loader.LoadMasterKeys()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master key")
		return nil, err
	}
	return keystoreV2.NewSCellSuite(encryption, signature)
}
