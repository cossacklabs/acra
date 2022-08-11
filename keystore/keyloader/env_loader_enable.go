package keyloader

import (
	"github.com/cossacklabs/acra/keystore"
)

func init() {
	RegisterKeyEncryptorFabric(KeystoreStrategyEnvMasterKey, NewEnvKeyEncryptorFabric(keystore.AcraMasterKeyVarName))
}
