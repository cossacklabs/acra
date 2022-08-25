package consul

import (
	"flag"
	"fmt"
	"net/url"
	"os"

	"github.com/cossacklabs/acra/encryptor"
	"github.com/hashicorp/consul/api"
	log "github.com/sirupsen/logrus"
)

// StorageCreator implement config_loader.EncryptorConfigStorage via Hashicorp Consul Backend
type StorageCreator struct{}

// IsStorageConfigured check weather CLI flag for Consul using was provided
func (s StorageCreator) IsStorageConfigured(flags *flag.FlagSet, prefix string) bool {
	if cliOptions := ParseCLIParametersFromFlags(flags, prefix); cliOptions.Address != "" {
		return true
	}
	return false
}

// RegisterCLIParameters register CLI flags for FlagSet for Hashicorp Consul Backend
func (s StorageCreator) RegisterCLIParameters(flags *flag.FlagSet, prefix, description string) {
	RegisterCLIParametersWithFlagSet(flags, prefix, description)
}

// NewStorage create config_loader.EncryptorConfigStorage from FlagSet
func (s StorageCreator) NewStorage(flags *flag.FlagSet, prefix string) (encryptor.ConfigStorage, error) {
	cliOptions := ParseCLIParametersFromFlags(flags, prefix)

	consulURL, err := url.ParseRequestURI(cliOptions.Address)
	if err != nil {
		return Storage{}, err
	}

	config := api.Config{
		Address: consulURL.Host,
		Scheme:  consulURL.Scheme,
	}

	if cliOptions.EnableTLS {
		log.Infoln("Configuring TLS connection to HashiCorp Consul")

		config.TLSConfig = cliOptions.TLSConfig()
	}

	client, err := api.NewClient(&config)
	if err != nil {
		return Storage{}, err
	}

	log.Infof("Load encryptor configuration from HashiCorp Consul with path %s ...", cliOptions.EncryptorConfigPath)
	return Storage{
		client:              client.KV(),
		encryptorConfigPath: cliOptions.EncryptorConfigPath,
	}, nil
}

// Storage implementation config_loader.EncryptorConfigStorage
type Storage struct {
	client              *api.KV
	encryptorConfigPath string
}

// GetEncryptorConfigPath implementation of config_loader.EncryptorConfigStorage
func (s Storage) GetEncryptorConfigPath() string {
	return s.encryptorConfigPath
}

// ReadFile implementation of filesystem.Storage interface
func (s Storage) ReadFile(path string) ([]byte, error) {
	kvPair, _, err := s.client.Get(path, nil)
	if err != nil {
		return nil, err
	}
	// If no value was found return false
	if kvPair == nil {
		return nil, fmt.Errorf("no value found in Consul by key %s", path)
	}
	return kvPair.Value, nil
}

// WriteFile implementation of filesystem.Storage interface
func (s Storage) WriteFile(path string, data []byte, perm os.FileMode) error {
	kvPair := api.KVPair{
		Key:   path,
		Value: data,
	}
	_, err := s.client.Put(&kvPair, nil)
	if err != nil {
		return err
	}

	return nil
}

// Remove implementation of filesystem.Storage interface
func (s Storage) Remove(path string) error {
	_, err := s.client.Delete(path, nil)
	return err
}

// Stat implementation of filesystem.Storage interface
func (s Storage) Stat(path string) (os.FileInfo, error) {
	//TODO implement me
	panic("implement me")
}

// Exists implementation of filesystem.Storage interface
func (s Storage) Exists(path string) (bool, error) {
	//TODO implement me
	panic("implement me")
}

// ReadDir implementation of filesystem.Storage interface
func (s Storage) ReadDir(path string) ([]os.FileInfo, error) {
	//TODO implement me
	panic("implement me")
}

// MkdirAll implementation of filesystem.Storage interface
func (s Storage) MkdirAll(path string, perm os.FileMode) error {
	//TODO implement me
	panic("implement me")
}

// Rename implementation of filesystem.Storage interface
func (s Storage) Rename(oldpath, newpath string) error {
	//TODO implement me
	panic("implement me")
}

// TempFile implementation of filesystem.Storage interface
func (s Storage) TempFile(pattern string, perm os.FileMode) (string, error) {
	//TODO implement me
	panic("implement me")
}

// TempDir implementation of filesystem.Storage interface
func (s Storage) TempDir(pattern string, perm os.FileMode) (string, error) {
	//TODO implement me
	panic("implement me")
}

// Link implementation of filesystem.Storage interface
func (s Storage) Link(oldpath, newpath string) error {
	//TODO implement me
	panic("implement me")
}

// Copy implementation of filesystem.Storage interface
func (s Storage) Copy(src, dst string) error {
	//TODO implement me
	panic("implement me")
}

// RemoveAll implementation of filesystem.Storage interface
func (s Storage) RemoveAll(path string) error {
	//TODO implement me
	panic("implement me")
}
