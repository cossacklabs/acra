//go:build !kms_keyloader_off
// +build !kms_keyloader_off

package kms

import "github.com/cossacklabs/acra/keystore/keyloader"

func init() {
	keyloader.RegisterKeyLoaderCreator(keyloader.KeystoreStrategyKMSMasterKey, func() (keyloader.MasterKeyLoader, error) {
		return NewMasterKeyLoader(&kmsOptions)
	})
}
