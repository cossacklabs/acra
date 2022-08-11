//go:build !kms_key_per_client_off
// +build !kms_key_per_client_off

package kms

import (
	"github.com/cossacklabs/acra/keystore/keyloader"
)

func init() {
	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyKMSPerClient, PerClientKeyEncryptorFabric{})
}
