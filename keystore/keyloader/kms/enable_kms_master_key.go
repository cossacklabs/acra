//go:build !kms_key_master_key_off
// +build !kms_key_master_key_off

package kms

import (
	"github.com/cossacklabs/acra/keystore/keyloader"
)

func init() {
	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyKMSMasterKey, KeyEncryptorFabric{})
}
