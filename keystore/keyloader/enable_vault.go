//go:build !vault_master_key_off
// +build !vault_master_key_off

package keyloader

import (
	"github.com/cossacklabs/acra/keystore/keyloader/hashicorp"
)

func init() {
	RegisterKeyEncryptorFabric(KeystoreStrategyHashicorpVaultMasterKey, hashicorp.KeyEncryptorFabric{})
}
