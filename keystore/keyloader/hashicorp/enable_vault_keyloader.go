//go:build !vault_keyloader_off
// +build !vault_keyloader_off

package hashicorp

import (
	"github.com/cossacklabs/acra/keystore/keyloader"
)

func init() {
	keyloader.RegisterKeyLoaderCreator(keyloader.KeystoreStrategyHashicorpVaultMasterKey, func() (keyloader.MasterKeyLoader, error) {
		return NewMasterKeyLoader(&vaultOptions)
	})
}
