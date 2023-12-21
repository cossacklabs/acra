//go:build !consul_encryptor_config_loader_off
// +build !consul_encryptor_config_loader_off

package config_loader

import "github.com/cossacklabs/acra/encryptor/base/config_loader/consul"

func init() {
	RegisterEncryptorConfigStorageCreator(EncryptoConfigStorageTypeConsul, consul.StorageCreator{})
}
