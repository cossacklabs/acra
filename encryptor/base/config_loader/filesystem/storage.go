package filesystem

import (
	"flag"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/utils/args"
	log "github.com/sirupsen/logrus"

	encryptor "github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/keystore/filesystem"
)

// StorageCreator implement config_loader.EncryptorConfigStorage via filesystem
type StorageCreator struct{}

// NewStorage create new filesystem encryptor.ConfigStorage
func (s StorageCreator) NewStorage(extractor *args.ServiceExtractor, prefix string) (encryptor.ConfigStorage, error) {
	cliOptions := ParseCLIParametersFromFlags(extractor, prefix)

	log.Infof("Load encryptor configuration from %s ...", cliOptions.EncryptorConfigFile)
	return &Storage{
		encryptorConfigFile: cliOptions.EncryptorConfigFile,
	}, nil
}

// IsStorageConfigured check weather CLI flag for filesystem using was provided
func (s StorageCreator) IsStorageConfigured(extractor *args.ServiceExtractor, prefix string) bool {
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
