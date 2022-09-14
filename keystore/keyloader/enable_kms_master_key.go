//go:build !kms_key_master_key_off
// +build !kms_key_master_key_off

package keyloader

func init() {
	RegisterKeyEncryptorFabric(KeystoreStrategyKMSMasterKey, KmsMasterKeyEncryptorFabric{})
}
