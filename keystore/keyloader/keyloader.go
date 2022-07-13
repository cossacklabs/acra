package keyloader

import (
	"github.com/cossacklabs/acra/keystore"
	log "github.com/sirupsen/logrus"
)

// CliMasterKeyLoaderCreator represent interface for all creators of MasterKeyLoader
type CliMasterKeyLoaderCreator interface {
	New() (MasterKeyLoader, error)
}

// MasterKeyLoader interface for loading ACRA_MASTER_KEYs from different sources.
type MasterKeyLoader interface {
	LoadMasterKey() (key []byte, err error)
	LoadMasterKeys() (encryption []byte, signature []byte, err error)
}

// GetInitializedMasterKeyLoader returns initialized MasterKeyLoader interface depending on hashicorp vault params
// with predefined ACRA_MASTER_KEY env name
func GetInitializedMasterKeyLoader(creators ...CliMasterKeyLoaderCreator) (keyLoader MasterKeyLoader, err error) {
	return initMasterKeyLoaderWithEnv(keystore.AcraMasterKeyVarName, creators...)
}

// GetInitializedMasterKeyLoaderWithEnv returns initialized MasterKeyLoader interface depending on hashicorp vault params and env name
func GetInitializedMasterKeyLoaderWithEnv(envVarName string, creators ...CliMasterKeyLoaderCreator) (keyLoader MasterKeyLoader, err error) {
	return initMasterKeyLoaderWithEnv(envVarName, creators...)
}

// initMasterKeyLoaderWithEnv returns initialized MasterKeyLoader interface depending on incoming params,
// via provided CliMasterKeyLoaderCreator
// otherwise EnvLoader with env name will be returned.
func initMasterKeyLoaderWithEnv(envVarName string, creators ...CliMasterKeyLoaderCreator) (keyLoader MasterKeyLoader, err error) {
	log.Infof("Initializing ACRA_MASTER_KEY loader...")

	for _, creator := range creators {
		masterKeyLoader, err := creator.New()
		if err != nil {
			return nil, err
		}

		if masterKeyLoader != nil {
			return masterKeyLoader, nil
		}
	}

	log.Infof("Initialized default env %s loader", envVarName)
	return NewEnvLoader(envVarName), nil
}
