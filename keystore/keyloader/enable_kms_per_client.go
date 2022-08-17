//go:build !kms_key_per_client_off
// +build !kms_key_per_client_off

package keyloader

import (
	"github.com/cossacklabs/acra/keystore/keyloader/kms"
)

func init() {
	RegisterKeyEncryptorFabric(KeystoreStrategyKMSPerClient, kms.PerClientKeyEncryptorFabric{})
}
