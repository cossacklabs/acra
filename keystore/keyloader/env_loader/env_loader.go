package env_loader

import (
	"github.com/cossacklabs/acra/keystore"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	log "github.com/sirupsen/logrus"
)

// EnvLoader unifying structure for implementation env MasterKeyLoader
type EnvLoader struct {
	MasterKeyEnv string
}

// NewEnvLoader return key loader using env variable
func NewEnvLoader(env string) EnvLoader {
	log.Infof("Initializing default env %s loader", env)
	return EnvLoader{
		MasterKeyEnv: env,
	}
}

// LoadMasterKey retrieve ACRA_MASTER_KEY from env variable and validate it
func (e EnvLoader) LoadMasterKey() (key []byte, err error) {
	return keystore.GetMasterKeyFromEnvironmentVariable(e.MasterKeyEnv)
}

// LoadMasterKeys retrieve ACRA_MASTER_KEY from env variable, deserialize and validate it
func (e EnvLoader) LoadMasterKeys() ([]byte, []byte, error) {
	return keystoreV2.GetMasterKeysFromEnvironmentVariable(e.MasterKeyEnv)
}
