package keyloader

import (
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/keyloader/env_loader"
)

func init() {
	RegisterKeyEncryptorFabric(KeystoreStrategyEnvMasterKey, env_loader.NewEnvKeyEncryptorFabric(keystore.AcraMasterKeyVarName))
}
