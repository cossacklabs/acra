/*
 * Copyright 2020, Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package keys

import (
	"errors"
	"flag"
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/keystore/keyloader/hashicorp"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	filesystemBackendV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend"
	"github.com/go-redis/redis/v7"
	log "github.com/sirupsen/logrus"
)

// KeyStoreFactory should return one of those errors when it is not able to construct requested keystore.
var (
	ErrNotImplementedV1 = errors.New("not implemented for keystore v1")
)

// KeyStoreParameters are parameters for DefaultKeyStoreFactory.
type KeyStoreParameters interface {
	KeyDir() string
	KeyDirPublic() string

	RedisConfigured() bool
	RedisOptions() *redis.Options
	VaultCLIOptions() hashicorp.VaultCLIOptions
}

// CommonKeyStoreParameters is a mix-in of command line parameters for keystore construction.
type CommonKeyStoreParameters struct {
	keyDir       string
	keyDirPublic string

	redisOptions cmd.RedisOptions
	vaultOptions hashicorp.VaultCLIOptions
}

// KeyDir returns path to key directory.
func (p *CommonKeyStoreParameters) KeyDir() string {
	return p.keyDir
}

// KeyDirPublic returns path to public key directory (if different from key directory).
func (p *CommonKeyStoreParameters) KeyDirPublic() string {
	if p.keyDirPublic == "" {
		return p.keyDir
	}
	return p.keyDirPublic
}

// RedisConfigured returns true is Redis keystore has been configured.
func (p *CommonKeyStoreParameters) RedisConfigured() bool {
	return p.redisOptions.KeysConfigured()
}

// RedisOptions returns Redis configuration options for keystore.
func (p *CommonKeyStoreParameters) RedisOptions() *redis.Options {
	return p.redisOptions.KeysOptions()
}

// VaultCLIOptions returns Hashicorp Vault configuration options for ACRA_MASTER_KEY loading.
func (p *CommonKeyStoreParameters) VaultCLIOptions() hashicorp.VaultCLIOptions {
	return p.vaultOptions
}

// RegisterRedisWithPrefix registers redis options in given flag set, using additional prefix.
func (p *CommonKeyStoreParameters) RegisterRedisWithPrefix(flags *flag.FlagSet, prefix, description string) {
	p.redisOptions.RegisterKeyStoreParameters(flags, prefix, description)
}

// RegisterVaultWithPrefix registers HashiCorp vault options in given flag set, using additional prefix.
func (p *CommonKeyStoreParameters) RegisterVaultWithPrefix(flags *flag.FlagSet, prefix, description string) {
	p.vaultOptions.RegisterCLIParameters(flags, prefix, description)
}

// Register registers keystore flags with the given flag set.
func (p *CommonKeyStoreParameters) Register(flags *flag.FlagSet) {
	p.RegisterPrefixed(flags, DefaultKeyDirectory, "", "")
	p.redisOptions.RegisterKeyStoreParameters(flags, "", "")
	p.vaultOptions.RegisterCLIParameters(flags, "", "")
}

// RegisterPrefixed registers keystore flags with the given flag set, using given prefix and description.
func (p *CommonKeyStoreParameters) RegisterPrefixed(flags *flag.FlagSet, defaultKeysDir, flagPrefix, descriptionSuffix string) {
	if descriptionSuffix != "" {
		descriptionSuffix = " " + descriptionSuffix
	}
	flags.StringVar(&p.keyDir, flagPrefix+"keys_dir", defaultKeysDir, "path to key directory"+descriptionSuffix)
	flags.StringVar(&p.keyDirPublic, flagPrefix+"keys_dir_public", "", "path to key directory for public keys"+descriptionSuffix)
}

// OpenKeyStoreForReading opens a keystore suitable for reading keys.
func OpenKeyStoreForReading(params KeyStoreParameters) (keystore.ServerKeyStore, error) {
	keyLoader, err := keyloader.GetInitializedMasterKeyLoader(params.VaultCLIOptions())
	if err != nil {
		return nil, err
	}

	if IsKeyStoreV2(params) {
		return openKeyStoreV2(params, keyLoader)
	}
	return openKeyStoreV1(params, keyLoader)
}

// OpenKeyStoreForWriting opens a keystore suitable for modifications.
func OpenKeyStoreForWriting(params KeyStoreParameters) (keyStore keystore.KeyMaking, err error) {
	keyLoader, err := keyloader.GetInitializedMasterKeyLoader(params.VaultCLIOptions())
	if err != nil {
		return nil, err
	}

	if IsKeyStoreV2(params) {
		return openKeyStoreV2(params, keyLoader)
	}
	return openKeyStoreV1(params, keyLoader)
}

// OpenKeyStoreForExport opens a keystore suitable for export operations.
func OpenKeyStoreForExport(params KeyStoreParameters) (api.KeyStore, error) {
	keyLoader, err := keyloader.GetInitializedMasterKeyLoader(params.VaultCLIOptions())
	if err != nil {
		return nil, err
	}

	if IsKeyStoreV2(params) {
		return openKeyStoreV2(params, keyLoader)
	}
	// Export from keystore v1 is not supported right now
	return nil, ErrNotImplementedV1
}

// OpenKeyStoreForImport opens a keystore suitable for import operations.
func OpenKeyStoreForImport(params KeyStoreParameters) (api.MutableKeyStore, error) {
	keyLoader, err := keyloader.GetInitializedMasterKeyLoader(params.VaultCLIOptions())
	if err != nil {
		return nil, err
	}

	if IsKeyStoreV2(params) {
		return openKeyStoreV2(params, keyLoader)
	}
	// Export from keystore v1 is not supported right now
	return nil, ErrNotImplementedV1
}

func openKeyStoreV1(params KeyStoreParameters, loader keyloader.MasterKeyLoader) (*filesystem.KeyStore, error) {
	masterKey, err := loader.LoadMasterKey()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master key")
		return nil, err
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithError(err).Errorln("Failed to initialise Secure Cell encryptor")
		return nil, err
	}

	keyStore := filesystem.NewCustomFilesystemKeyStore()
	keyStore.Encryptor(scellEncryptor)
	keyDir := params.KeyDir()
	keyDirPublic := params.KeyDirPublic()
	if keyDir != keyDirPublic {
		keyStore.KeyDirectories(keyDir, keyDirPublic)
	} else {
		keyStore.KeyDirectory(keyDir)
	}

	if params.RedisConfigured() {
		redis := params.RedisOptions()
		keyStorage, err := filesystem.NewRedisStorage(redis.Addr, redis.Password, redis.DB, nil)
		if err != nil {
			log.WithError(err).Errorln("Failed to initialise Redis storage")
			return nil, err
		}
		keyStore.Storage(keyStorage)
	}

	keyStoreV1, err := keyStore.Build()
	if err != nil {
		log.WithError(err).Errorln("Failed to initialise keystore v1")
		return nil, err
	}
	return keyStoreV1, nil
}

func openKeyStoreV2(params KeyStoreParameters, loader keyloader.MasterKeyLoader) (*keystoreV2.ServerKeyStore, error) {
	encryption, signature, err := loader.LoadMasterKeys()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master key")
		return nil, err
	}
	suite, err := keystoreV2.NewSCellSuite(encryption, signature)
	if err != nil {
		log.WithError(err).Error("Failed to initialize Secure Cell crypto suite")
		return nil, err
	}

	var backend filesystemBackendV2.Backend
	if params.RedisConfigured() {
		config := &filesystemBackendV2.RedisConfig{
			RootDir: params.KeyDir(),
			Options: params.RedisOptions(),
		}
		backend, err = filesystemBackendV2.CreateRedisBackend(config)
		if err != nil {
			log.WithError(err).Error("Cannot connect to Redis keystore")
			return nil, err
		}
	} else {
		backend, err = filesystemBackendV2.CreateDirectoryBackend(params.KeyDir())
		if err != nil {
			log.WithError(err).Error("Cannot open key directory")
			return nil, err
		}
	}

	keyDirectory, err := filesystemV2.CustomKeyStore(backend, suite)
	if err != nil {
		log.WithError(err).Error("Failed to initialize key directory")
		return nil, err
	}
	return keystoreV2.NewServerKeyStore(keyDirectory), nil
}

// IsKeyStoreV2 checks if the directory contains a keystore version 2 from KeyStoreParameters
func IsKeyStoreV2(params KeyStoreParameters) bool {
	if params.RedisConfigured() {
		redisOption := params.RedisOptions()
		redisClient, err := filesystemBackendV2.OpenRedisBackend(&filesystemBackendV2.RedisConfig{
			RootDir: params.KeyDir(),
			Options: &redis.Options{
				Addr:     redisOption.Addr,
				Password: redisOption.Password,
				DB:       redisOption.DB,
			},
		})
		if err != nil {
			log.WithError(err).Debugln("Failed to find keystore v2 in Redis")
			return false
		}
		// If the keystore has been opened successfully, it definitely exists.
		redisClient.Close()
		return true
	}
	// Otherwise, check the local filesystem storage provided by Acra CE.
	return filesystemBackendV2.CheckDirectoryVersion(params.KeyDir()) == nil
}

// IsKeyStoreV1 checks if the directory contains a keystore version 1 from KeyStoreParameters
func IsKeyStoreV1(params KeyStoreParameters) bool {
	var fsStorage filesystem.Storage = &filesystem.DummyStorage{}
	if params.RedisConfigured() {
		redisOption := params.RedisOptions()
		redisStorage, err := filesystem.NewRedisStorage(redisOption.Addr, redisOption.Password, redisOption.DB, nil)
		if err != nil {
			log.WithError(err).Debug("Failed to open redis storage for version check")
			return false
		}
		fsStorage = redisStorage
	}

	keyDirectory := params.KeyDir()
	fi, err := fsStorage.Stat(keyDirectory)
	if err != nil {
		log.WithError(err).WithField("path", keyDirectory).Debug("Failed to stat key directory for version check")
		return false
	}
	if !fi.IsDir() {
		log.WithField("path", keyDirectory).Debug("Key directory is not a directory")
		return false
	}
	files, err := fsStorage.ReadDir(keyDirectory)
	if err != nil {
		log.WithError(err).WithField("path", keyDirectory).Debug("Failed to read key directory for version check")
		return false
	}
	if len(files) == 0 {
		log.WithField("path", keyDirectory).Debug("Key directory is empty")
		return false
	}
	return true
}
