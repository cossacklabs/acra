package env_loader

import (
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/keyloader"
)

func init() {
	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyEnvMasterKey, NewKeyEncryptorFabric(keystore.AcraMasterKeyVarName))
}
