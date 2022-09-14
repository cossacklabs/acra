//go:build !kms_key_per_client_off
// +build !kms_key_per_client_off

package keyloader

import (
	"github.com/cossacklabs/acra/keystore/keyloader/kms"
	"github.com/cossacklabs/acra/keystore/kms/aws"
)

func init() {
	RegisterKeyEncryptorFabric(KeystoreStrategyKMSPerClient, KmsPerClientKeyEncryptorFabric{})
	RegisterKeystoreStrategyKeyMapper(KeystoreStrategyKMSPerClient, kms.TypeAWS, aws.NewKMSPerClientKeyMapper())
}
