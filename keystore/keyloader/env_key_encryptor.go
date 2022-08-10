package keyloader

import (
	"github.com/cossacklabs/acra/keystore"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	log "github.com/sirupsen/logrus"
)

// EnvKeyEncryptorFabric implementation of keyloader.KeyEncryptorFabric for `env_master_key` strategy
type EnvKeyEncryptorFabric struct {
	envName string
}

// NewEnvKeyEncryptorFabric create new KeyEncryptorFabric
func NewEnvKeyEncryptorFabric(envName string) KeyEncryptorFabric {
	return EnvKeyEncryptorFabric{
		envName,
	}
}

// NewKeyEncryptor fabric of keystore.KeyEncryptor for `env_master_key` strategy
func (k EnvKeyEncryptorFabric) NewKeyEncryptor() (keystore.KeyEncryptor, error) {
	loader := NewEnvLoader(k.envName)

	key, err := loader.LoadMasterKey()
	if err != nil {
		return nil, err
	}
	return keystore.NewSCellKeyEncryptor(key)
}

// NewKeyEncryptorSuite fabric of crypto.KeyStoreSuite for `env_master_key` strategy
func (k EnvKeyEncryptorFabric) NewKeyEncryptorSuite() (*crypto.KeyStoreSuite, error) {
	loader := NewEnvLoader(k.envName)

	encryption, signature, err := loader.LoadMasterKeys()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master key")
		return nil, err
	}
	return keystoreV2.NewSCellSuite(encryption, signature)
}
