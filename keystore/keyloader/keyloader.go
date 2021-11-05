package keyloader

import (
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/keyloader/hashicorp"

	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

// MasterKeyLoader interface for loading ACRA_MASTER_KEYs from different sources.
type MasterKeyLoader interface {
	LoadMasterKey() (key []byte, err error)
	LoadMasterKeys() (encryption []byte, signature []byte, err error)
}

// GetInitializedMasterKeyLoader returns initialized MasterKeyLoader interface depending on hashicorp vault params
// with predefined ACRA_MASTER_KEY env name
func GetInitializedMasterKeyLoader(vaultParams hashicorp.VaultCLIOptions) (keyLoader MasterKeyLoader, err error) {
	return initMasterKeyLoaderWithEnv(keystore.AcraMasterKeyVarName, vaultParams)
}

// GetInitializedMasterKeyLoaderWithEnv returns initialized MasterKeyLoader interface depending on hashicorp vault params and env name
func GetInitializedMasterKeyLoaderWithEnv(envVarName string, vaultParams hashicorp.VaultCLIOptions) (keyLoader MasterKeyLoader, err error) {
	return initMasterKeyLoaderWithEnv(envVarName, vaultParams)
}

// initMasterKeyLoaderWithEnv returns initialized MasterKeyLoader interface depending on incoming params,
// if HashiCorp Vault connection address is provided, hashicorp.VaultLoader will be initialized,
// otherwise EnvLoader with env name will be returned.
func initMasterKeyLoaderWithEnv(envVarName string, vaultParams hashicorp.VaultCLIOptions) (keyLoader MasterKeyLoader, err error) {
	log.Infof("Initializing ACRA_MASTER_KEY loader...")

	if vaultParams.Address != "" {
		log.Infoln("Initializing connection to HashiCorp Vault for ACRA_MASTER_KEY loading")

		vaultConfig := api.DefaultConfig()
		vaultConfig.Address = vaultParams.Address

		if vaultParams.EnableTLS {
			log.Infoln("Configuring TLS connection to HashiCorp Vault")

			if err := vaultConfig.ConfigureTLS(vaultParams.TLSConfig()); err != nil {
				return nil, err
			}
		}

		keyLoader, err = hashicorp.NewVaultLoader(vaultConfig, vaultParams.SecretsPath)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize HashiCorp Vault loader")
			return
		}
		log.Infoln("Initialized HashiCorp Vault ACRA_MASTER_KEY loader")
		return
	}

	log.Infof("Initialized default env %s loader", envVarName)
	return NewEnvLoader(envVarName), nil
}
