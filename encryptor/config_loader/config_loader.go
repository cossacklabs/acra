package config_loader

import (
	"encoding/base64"
	"errors"
	"flag"
	"sync"

	"github.com/cossacklabs/acra/encryptor"
	log "github.com/sirupsen/logrus"
)

// represent all possible encryptor config loader types
const (
	EncryptoConfigStorageTypeConsul     = "consul"
	EncryptoConfigStorageTypeFilesystem = "filesystem"
)

// SupportedEncryptorConfigStorages contains all possible values for flag `--encryptor_config_storage_type`
var SupportedEncryptorConfigStorages = []string{
	EncryptoConfigStorageTypeConsul,
	EncryptoConfigStorageTypeFilesystem,
}

var (
	// ErrEncryptorConfigStorageNotFound represent an error of missing EncryptorConfigStorage in registry
	ErrEncryptorConfigStorageNotFound = errors.New("ErrEncryptorConfigStorageNotFound not found by storage type")
	lock                              = sync.Mutex{}
)

// EncryptorConfigStorageCreator describe interface for creating EncryptorConfigStorage
type EncryptorConfigStorageCreator interface {
	NewStorage(flags *flag.FlagSet, prefix string) (encryptor.ConfigStorage, error)
	RegisterCLIParameters(flags *flag.FlagSet, prefix, description string)
	IsStorageConfigured(flags *flag.FlagSet, prefix string) bool
}

var configStorageCreators = map[string]EncryptorConfigStorageCreator{}

// RegisterEncryptorConfigStorageCreator add new filesystem.Storage to registry
func RegisterEncryptorConfigStorageCreator(name string, creator EncryptorConfigStorageCreator) {
	lock.Lock()
	configStorageCreators[name] = creator
	lock.Unlock()
	log.WithField("name", name).Debug("Registered config StorageBackendCreator")
}

// GetEncryptorConfigStorage returns initialized filesystem.Storage interface depending on incoming storage type
func GetEncryptorConfigStorage(storageType string, flags *flag.FlagSet, prefix string) (encryptor.ConfigStorage, error) {
	creator, ok := configStorageCreators[storageType]
	if !ok {
		log.WithField("storage-type", storageType).Warnf("encryptor.ConfigStorage not found")
		return nil, ErrEncryptorConfigStorageNotFound
	}

	return creator.NewStorage(flags, prefix)
}

// ConfigLoader load encryptor config using encryptor.ConfigStorage
type ConfigLoader struct {
	configStorage encryptor.ConfigStorage
}

// NewConfigLoader create new ConfigLoader
func NewConfigLoader(storageType string, flags *flag.FlagSet, prefix string) (*ConfigLoader, error) {
	configStorage, err := GetEncryptorConfigStorage(storageType, flags, prefix)
	if err != nil {
		return nil, err
	}

	return &ConfigLoader{configStorage}, nil
}

// Load load EncryptorConfig using encryptor.ConfigStorage
func (c *ConfigLoader) Load() ([]byte, error) {
	configPath := c.configStorage.GetEncryptorConfigPath()

	encryptorConfig, err := c.configStorage.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	// EncryptorConfig from filesystem should be in plaintext
	if decoded, err := base64.StdEncoding.DecodeString(string(encryptorConfig)); err == nil {
		log.Debug("base64 encoded EncryptorConfig detected")
		encryptorConfig = decoded
	}

	return encryptorConfig, nil
}

// RegisterEncryptorConfigLoaderCLIWithFlags register flags for all fabrics
func RegisterEncryptorConfigLoaderCLIWithFlags(flag *flag.FlagSet, prefix, description string) {
	for _, v := range configStorageCreators {
		v.RegisterCLIParameters(flag, prefix, description)
	}
}

// IsEncryptorConfigLoaderCLIConfiguredWithFlags check weather CLI ConfigStorage flags of FlagSet were configured
func IsEncryptorConfigLoaderCLIConfiguredWithFlags(flag *flag.FlagSet, prefix string) bool {
	for _, v := range configStorageCreators {
		if ok := v.IsStorageConfigured(flag, prefix); ok {
			return true
		}
	}

	return false
}

// RegisterEncryptorConfigLoaderParameters register flags for all fabrics with CommandLine flags
func RegisterEncryptorConfigLoaderParameters() {
	RegisterEncryptorConfigLoaderCLIWithFlags(flag.CommandLine, "", "")
}

// IsEncryptorConfigLoaderCLIConfigured check weather CLI ConfigStorage flags were configured
func IsEncryptorConfigLoaderCLIConfigured() bool {
	return IsEncryptorConfigLoaderCLIConfiguredWithFlags(flag.CommandLine, "")
}
