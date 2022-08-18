//go:build !kms_key_master_key_off
// +build !kms_key_master_key_off

package keyloader

import (
	"github.com/cossacklabs/acra/keystore/keyloader/kms"
)

func init() {
	RegisterKeyEncryptorFabric(KeystoreStrategyKMSMasterKey, kms.KeyEncryptorFabric{})
}
