package filesystem

import (
	"flag"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/keystore/filesystem"
)

// StorageCreator implement config_loader.EncryptorConfigStorage via filesystem
type StorageCreator struct{}

// NewStorage create new filesystem encryptor.ConfigStorage
func (s StorageCreator) NewStorage(extractor *cmd.ServiceParamsExtractor, prefix string) (encryptor.ConfigStorage, error) {
	cliOptions := ParseCLIParametersFromFlags(extractor, prefix)

	log.Infof("Load encryptor configuration from %s ...", cliOptions.EncryptorConfigFile)
	return &Storage{
		encryptorConfigFile: cliOptions.EncryptorConfigFile,
	}, nil
}

// IsStorageConfigured check weather CLI flag for filesystem using was provided
func (s StorageCreator) IsStorageConfigured(extractor *cmd.ServiceParamsExtractor, prefix string) bool {
	if cliOptions := ParseCLIParametersFromFlags(extractor, prefix); cliOptions.EncryptorConfigFile != "" {
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
