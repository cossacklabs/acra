package keyloader

import (
	"github.com/cossacklabs/acra/keystore"
)

// MasterKeyLoader interface for loading ACRA_MASTER_KEYs from different sources.
type MasterKeyLoader interface {
	LoadMasterKey() (key []byte, err error)
	LoadMasterKeys() (encryption []byte, signature []byte, err error)
}

// GetInitializedMasterKeyLoader returns initialized MasterKeyLoader interface depending on incoming load key strategy
// with predefined ACRA_MASTER_KEY env name
func GetInitializedMasterKeyLoader(loadStrategy string) (keyLoader MasterKeyLoader, err error) {
	return initMasterKeyLoaderWithEnv(keystore.AcraMasterKeyVarName, loadStrategy)
}

// GetInitializedMasterKeyLoaderWithEnv returns initialized MasterKeyLoader interface depending on incoming load key strategy
func GetInitializedMasterKeyLoaderWithEnv(envVarName string, loadStrategy string) (keyLoader MasterKeyLoader, err error) {
	return initMasterKeyLoaderWithEnv(envVarName, loadStrategy)
}

// initMasterKeyLoaderWithEnv returns initialized MasterKeyLoader interface depending on incoming load key strategy
// otherwise EnvLoader with env name will be returned.
func initMasterKeyLoaderWithEnv(envVarName string, loadStrategy string) (MasterKeyLoader, error) {
	cliParams := GetCLIParameters()
	switch loadStrategy {
	case KeystoreStrategyKMSMasterKey:
		return cliParams.GetKMSParameters().NewMasterKeyLoader()
	case KeystoreStrategyHashicorpVaultMasterKey:
		return cliParams.GetVaultCLIParameters().NewMasterKeyLoader()
	default:
		return NewEnvLoader(envVarName), nil
	}
}
