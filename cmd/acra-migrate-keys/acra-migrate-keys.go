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

// Package main is entry point for Acra key migration utility (`acra-migrate-keys`).
// It is used to convert between key store formats used by Acra.
//
// https://docs.cossacklabs.com/pages/documentation-acra/#key-management
package main

import (
	"errors"

	"github.com/cossacklabs/acra/cmd"
	migratekeys "github.com/cossacklabs/acra/cmd/acra-migrate-keys/migrate-keys"
	keystoreV1 "github.com/cossacklabs/acra/keystore"
	filesystemV1 "github.com/cossacklabs/acra/keystore/filesystem"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	keystoreApiV2 "github.com/cossacklabs/acra/keystore/v2/keystore/api"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

var (
	defaultConfigPath = utils.GetConfigPathByName("acra-migrate-keys")
	serviceName       = "acra-migrate-keys"
)

func main() {
	params := migratekeys.RegisterCommandLineParams()
	err := cmd.Parse(defaultConfigPath, serviceName)
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Fatal("Cannot parse arguments")
	}
	params.SetDefaults()

	if params.Src.KeyStoreVersion == "v1" && params.Dst.KeyStoreVersion == "v2" {
		keyStoreV1, err := OpenKeyStoreV1(migratekeys.OpenSrc, params.Src, params.Misc)
		if err != nil {
			log.WithError(err).Fatal("Failed to open keystore v1 (src)")
		}
		keyStoreV2, err := OpenKeyStoreV2(migratekeys.OpenDst, params.Dst, params.Misc)
		if err != nil {
			log.WithError(err).Fatal("Failed to open keystore v2 (dst)")
		}
		err = MigrateV1toV2(keyStoreV1, keyStoreV2, params.Misc)
		if err != nil {
			log.WithError(err).Fatal("Migration failed")
		}
		log.Infof("Migration complete")
		log.Infof("Old key store: %s", params.Src.KeyDir)
		log.Infof("New key store: %s", params.Dst.KeyDir)
		if params.Misc.DryRun {
			log.Infof("Run without --dry_run to actually write key data")
		}
		return
	}

	log.WithFields(log.Fields{"src": params.Src.KeyStoreVersion, "dst": params.Dst.KeyStoreVersion}).
		Fatal("Key store conversion not supported")
}

// MigrateV1toV2 transfers keys from key store v1 to v2.
func MigrateV1toV2(srcV1 filesystemV1.KeyExport, dstV2 keystoreV2.KeyFileImportV1, params migratekeys.MiscParams) error {
	log.Trace("Enumerating keys for export")
	keys, err := srcV1.EnumerateExportedKeys()
	if err != nil {
		log.WithError(err).Debug("Failed to enumerate exported keys")
		return err
	}
	log.Trace("Key enumeration complete")

	// We are going to import multiple keys. Some of them may not be successful.
	// Since we cannot rollback partial import, go on with processing remaining
	// keys on error. However, make sure that the operation as a whole fails if
	// not all keys have been imported successfully.
	actual := 0
	expected := len(keys)

	log.Tracef("Importing %d keys from keystore v1", expected)
	for _, key := range keys {
		log := log.WithField("purpose", key.Purpose).WithField("id", key.ID)
		err := dstV2.ImportKeyFileV1(srcV1, key)
		if err != nil {
			log.WithError(err).Warn("Failed to import key")
			continue
		}
		actual++
	}
	log.Tracef("Imported %d/%d keys from keystore v1", actual, expected)

	if actual != expected {
		return errors.New("Incomplete key import")
	}

	return nil
}

// OpenKeyStoreV1 opens key store v1 for given purpose.
func OpenKeyStoreV1(mode migratekeys.OpenMode, store migratekeys.KeyStoreParams, params migratekeys.MiscParams) (*filesystemV1.KeyStore, error) {
	masterKey, err := keystoreV1.GetMasterKeyFromEnvironment()
	if err != nil {
		log.WithError(err).Error("Cannot load master key")
		return nil, err
	}
	encryptor, err := keystoreV1.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithError(err).Error("Cannot init Secure Cell encryptor")
		return nil, err
	}
	var keyStore *filesystemV1.KeyStore
	if store.KeyDir != store.KeyDirPublic {
		keyStore, err = filesystemV1.NewFilesystemKeyStoreTwoPath(store.KeyDir, store.KeyDirPublic, encryptor)
	} else {
		keyStore, err = filesystemV1.NewFilesystemKeyStore(store.KeyDir, encryptor)
	}
	if err != nil {
		log.WithError(err).Error("Cannot init key store")
		return nil, err
	}
	return keyStore, nil
}

// OpenKeyStoreV2 opens key store v2 for given purpose.
func OpenKeyStoreV2(mode migratekeys.OpenMode, store migratekeys.KeyStoreParams, params migratekeys.MiscParams) (*keystoreV2.ServerKeyStore, error) {
	encryption, signature, err := keystoreV2.GetMasterKeysFromEnvironment()
	if err != nil {
		log.WithError(err).Error("Cannot read master keys from environment")
		return nil, err
	}
	suite, err := keystoreV2.NewSCellSuite(encryption, signature)
	if err != nil {
		log.WithError(err).Error("Failed to initialize Secure Cell crypto suite")
		return nil, err
	}
	path := store.KeyDir
	if mode == migratekeys.OpenDst {
		if filesystemV2.IsKeyDirectory(path) && !params.Force {
			log.WithField("path", path).Error("Key directory already exists")
			log.Info("Run with --force to import into existing directory")
			return nil, errors.New("destination exists")
		}
	}
	var keyDir keystoreApiV2.MutableKeyStore
	if mode == migratekeys.OpenDst && params.DryRun {
		keyDir, err = filesystemV2.NewInMemory(suite)
		if err != nil {
			log.WithError(err).Error("Cannot create in-memory key store")
			return nil, err
		}
	} else {
		keyDir, err = filesystemV2.OpenDirectoryRW(path, suite)
		if err != nil {
			log.WithError(err).WithField("path", path).Error("Cannot open key directory")
			return nil, err
		}
	}
	return keystoreV2.NewServerKeyStore(keyDir), nil
}
