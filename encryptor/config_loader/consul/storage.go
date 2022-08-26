package consul

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

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

	httpClient, err := cliOptions.ConsulHttpClient(flags)
	if err != nil {
		return nil, err
	}

	config := api.Config{
		Address:    cliOptions.Address,
		HttpClient: httpClient,
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

const maxTempFileAttempts = 10

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
		return nil, os.ErrNotExist
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
	pair, _, err := s.client.Get(path, nil)
	if err != nil {
		return nil, err
	}
	if pair != nil {
		// base64 returns approximate length which may be slightly bigger than necessary,
		// but we don't really care about accuracy. We only need to know whether it's zero
		// or non-zero as some os.FileInfo users depend on that.
		// Also, this will overflow for keys larger than "int", but we shouldn't have such.
		return newFileInfo(path, base64.StdEncoding.DecodedLen(len(pair.Value)), false), nil
	}
	// If a key does not exist at given pRath then it might be a directory
	// if the path is a prefix of some existing key.
	pairs, _, err := s.client.List(makeDir(path), nil)
	if err != nil {
		return nil, err
	}
	if len(pairs) > 0 {
		return newFileInfo(path, 0, true), nil
	}
	// Otherwise, there is no such file.
	return nil, os.ErrNotExist
}

// Exists implementation of filesystem.Storage interface
func (s Storage) Exists(path string) (bool, error) {
	kvPair, _, err := s.client.Get(path, nil)
	if err != nil {
		return false, err
	}
	return kvPair == nil, nil
}

// ReadDir implementation of filesystem.Storage interface
func (s Storage) ReadDir(path string) ([]os.FileInfo, error) {
	kvPairs, _, err := s.client.List(makeDir(path), nil)
	if err != nil {
		return nil, err
	}
	// We do not distinguish between empty directories and missing directories.
	// However, keystore never creates empty directories so assume it's missing.
	if len(kvPairs) == 0 {
		return nil, os.ErrNotExist
	}

	// Scan will traverse all 'subdirectories' too, but we want only direct children.
	// Currently we should not have nested directories but handle them just in case.
	prefix := path + "/"
	infos := make([]os.FileInfo, 0, len(kvPairs))
	seenDirectories := make(map[string]struct{})
	for _, keyPair := range kvPairs {
		name := strings.TrimPrefix(keyPair.Key, prefix)
		idx := strings.Index(name, "/")
		if idx == -1 {
			infos = append(infos, newFileInfo(name, 0, false))
		} else {
			dirName := name[0:idx]
			_, seen := seenDirectories[dirName]
			if !seen {
				infos = append(infos, newFileInfo(dirName, 0, true))
				seenDirectories[dirName] = struct{}{}
			}
		}
	}
	return infos, nil
}

// MkdirAll implementation of filesystem.Storage interface
func (s Storage) MkdirAll(path string, perm os.FileMode) error {
	// We don't maintain hierarchy in Consul directly, it's all in key names
	return nil
}

// Rename implementation of filesystem.Storage interface
func (s Storage) Rename(oldpath, newpath string) error {
	if err := s.Copy(oldpath, newpath); err != nil {
		return err
	}
	return s.Remove(oldpath)
}

// TempFile implementation of filesystem.Storage interface
func (s Storage) TempFile(pattern string, perm os.FileMode) (string, error) {
	for i := 0; i < maxTempFileAttempts; i++ {
		kvPair := api.KVPair{
			Key:   pattern + fmt.Sprintf("%06d", rand.Int()),
			Value: []byte{},
		}

		_, err := s.client.Put(&kvPair, nil)
		if err == nil {
			return kvPair.Key, nil
		}
	}
	return "", errors.New("failed to create temporary file")
}

// TempDir implementation of filesystem.Storage interface
func (s Storage) TempDir(pattern string, perm os.FileMode) (string, error) {
	for i := 0; i < maxTempFileAttempts; i++ {
		path := pattern + fmt.Sprintf(".%06d", rand.Int())
		kvPair, _, err := s.client.Get(path, nil)
		if err != nil || len(kvPair.Value) > 0 {
			continue
		}
		kvPairs, _, err := s.client.List(makeDir(path), nil)
		if err != nil || len(kvPairs) > 0 {
			continue
		}
		return path, nil
	}
	return "", errors.New("failed to create temporary dir")
}

// Link implementation of filesystem.Storage interface
func (s Storage) Link(oldpath, newpath string) error {
	// Consul KV does not support hard links for keys. Please copy.
	return errors.New("operation not supported")
}

// Copy implementation of filesystem.Storage interface
func (s Storage) Copy(src, dst string) error {
	data, err := s.ReadFile(src)
	if err != nil {
		return err
	}

	kvPair := api.KVPair{
		Key:   dst,
		Value: data,
	}
	_, err = s.client.Put(&kvPair, nil)
	if err != nil {
		return err
	}
	return nil
}

func makeDir(path string) string {
	if strings.HasSuffix(path, "/") {
		return path
	}
	return path + "/"
}

// RemoveAll implementation of filesystem.Storage interface
func (s Storage) RemoveAll(path string) error {
	_, err := s.client.DeleteTree(path, nil)
	return err
}

type fileInfo struct {
	name  string
	size  int
	isDir bool
}

func newFileInfo(name string, size int, isDir bool) *fileInfo {
	return &fileInfo{
		name:  name,
		size:  size,
		isDir: isDir,
	}
}

func (fi *fileInfo) Name() string {
	return fi.name
}

func (fi *fileInfo) Size() int64 {
	return int64(fi.size)
}

func (fi *fileInfo) Mode() os.FileMode {
	return os.FileMode(0600)
}

func (fi *fileInfo) ModTime() time.Time {
	return time.Time{}
}

func (fi *fileInfo) IsDir() bool {
	return fi.isDir
}

func (fi *fileInfo) Sys() interface{} {
	return nil
}
