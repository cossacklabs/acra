package filesystem

import (
	"flag"

	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/keystore/filesystem"
	log "github.com/sirupsen/logrus"
)

// StorageCreator implement config_loader.EncryptorConfigStorage via filesystem
type StorageCreator struct{}

func (s StorageCreator) NewStorage(flags *flag.FlagSet, prefix string) (encryptor.ConfigStorage, error) {
	cliOptions := ParseCLIParametersFromFlags(flags, prefix)

	log.Infof("Load encryptor configuration from %s ...", cliOptions.EncryptorConfigFile)
	return &Storage{
		encryptorConfigFile: cliOptions.EncryptorConfigFile,
	}, nil
}

// StorageConfigured check weather CLI flag for filesystem using was provided
func (s StorageCreator) StorageConfigured(flags *flag.FlagSet, prefix string) bool {
	if cliOptions := ParseCLIParametersFromFlags(flags, prefix); cliOptions.EncryptorConfigFile != "" {
		return true
	}
	return false
}

// RegisterCLIParameters register CLI flags for FlagSet for filesystem
func (s StorageCreator) RegisterCLIParameters(flags *flag.FlagSet, prefix, description string) {
	RegisterCLIParametersWithFlagSet(flags, prefix, description)
}

// Storage filesystem.FileStorage wrapper of config_loader.EncryptorConfigStorage
type Storage struct {
	filesystem.FileStorage
	encryptorConfigFile string
}

// GetEncryptorConfigPath implementation of config_loader.EncryptorConfigStorage method
func (s Storage) GetEncryptorConfigPath() string {
	return s.encryptorConfigFile
}
