package keyloader

import "github.com/cossacklabs/acra/keystore"

// MasterKeyLoader interface for loading ACRA_MASTER_KEYs from different sources.
type MasterKeyLoader interface {
	LoadMasterKey() (key []byte, err error)
	LoadMasterKeys() (encryption []byte, signature []byte, err error)
}

// MasterKeyLoaderFactory interface for creating ACRA_MASTER_KEYs loaders from different sources.
type MasterKeyLoaderFactory interface {
	CreateMasterKeyLoader() (MasterKeyLoader, error)
}

// GetInitializedMasterKeyLoader returns initialized MasterKeyLoader interface depending on incoming load key strategy
// with predefined ACRA_MASTER_KEY env name
func GetInitializedMasterKeyLoader(masterKeyLoaderFactory MasterKeyLoaderFactory) (keyLoader MasterKeyLoader, err error) {
	return masterKeyLoaderFactory.CreateMasterKeyLoader()
}

// MasterKeyLoaderCreator implementation of MasterKeyLoaderFactory depending on load strategy
type MasterKeyLoaderCreator struct {
	loadStrategy string
	envName      string
}

// NewMasterKeyLoaderFactory create new MasterKeyLoaderCreator with specified load strategy
func NewMasterKeyLoaderFactory(loadStrategy string) MasterKeyLoaderFactory {
	return MasterKeyLoaderCreator{
		loadStrategy: loadStrategy,
		envName:      keystore.AcraMasterKeyVarName,
	}
}

// NewMasterKeyLoaderFactoryWithEnv create new MasterKeyLoaderCreator with specified envName
func NewMasterKeyLoaderFactoryWithEnv(envName string) MasterKeyLoaderFactory {
	return MasterKeyLoaderCreator{
		envName: keystore.AcraMasterKeyVarName,
	}
}

func (m MasterKeyLoaderCreator) CreateMasterKeyLoader() (MasterKeyLoader, error) {
	cliParams := GetCLIParameters()
	switch m.loadStrategy {
	case KeystoreStrategyKMSMasterKey:
		return NewKMSMasterKeyLoader(cliParams.GetKMSParameters())
	case KeystoreStrategyHashicorpVaultMasterKey:
		return NewVaultMasterKeyLoader(cliParams.GetVaultCLIParameters())
	default:
		return NewEnvLoader(m.envName), nil
	}
}
