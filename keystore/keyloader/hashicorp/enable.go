//go:build !vault_master_key_off
// +build !vault_master_key_off

package hashicorp

import "github.com/cossacklabs/acra/keystore/keyloader"

func init() {
	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyHashicorpVaultMasterKey, KeyEncryptorFabric{})
}
