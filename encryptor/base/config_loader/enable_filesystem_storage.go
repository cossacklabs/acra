package config_loader

import "github.com/cossacklabs/acra/encryptor/base/config_loader/filesystem"

func init() {
	RegisterEncryptorConfigStorageCreator(EncryptoConfigStorageTypeFilesystem, &filesystem.StorageCreator{})
}
