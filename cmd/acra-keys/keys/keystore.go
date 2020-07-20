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

	"github.com/cossacklabs/acra/keystore"
	keystoreV1 "github.com/cossacklabs/acra/keystore"
	filesystemV1 "github.com/cossacklabs/acra/keystore/filesystem"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	log "github.com/sirupsen/logrus"
)

// KeyStoreFactory defines how to construct key stores by parameters.
// Export and import are available only for key store v2 so they are kept separate,
// return an error if they cannot be provided (e.g, key store v1 is requested).
type KeyStoreFactory interface {
	OpenKeyStoreForReading(params *CommandLineParams) (keystore.ServerKeyStore, error)
	OpenKeyStoreForWriting(params *CommandLineParams) (keystore.KeyMaking, error)
	OpenKeyStoreForExport(params *CommandLineParams) (api.KeyStore, error)
	OpenKeyStoreForImport(params *CommandLineParams) (api.MutableKeyStore, error)
}

// KeyStoreFactory should return one of those errors when it is not able to construct requested key store.
var (
	ErrNotImplementedV1 = errors.New("not implemented for key store v1")
)

// DefaultKeyStoreFactory it the default key store factory in Acra CE.
// It chooses appropriate key store type based on its content.
type DefaultKeyStoreFactory struct{}

// OpenKeyStoreForReading opens a key store suitable for reading keys.
func (*DefaultKeyStoreFactory) OpenKeyStoreForReading(params *CommandLineParams) (keystore.ServerKeyStore, error) {
	if filesystemV2.IsKeyDirectory(params.KeyDir) {
		return openKeyStoreV2(params)
	}
	return openKeyStoreV1(params)
}

// OpenKeyStoreForWriting opens a key store suitable for modifications.
func (*DefaultKeyStoreFactory) OpenKeyStoreForWriting(params *CommandLineParams) (keystore.KeyMaking, error) {
	if filesystemV2.IsKeyDirectory(params.KeyDir) {
		return openKeyStoreV2(params)
	}
	return openKeyStoreV1(params)
}

// OpenKeyStoreForExport opens a key store suitable for export operations.
func (*DefaultKeyStoreFactory) OpenKeyStoreForExport(params *CommandLineParams) (api.KeyStore, error) {
	if filesystemV2.IsKeyDirectory(params.KeyDir) {
		return openKeyStoreV2(params)
	}
	// Not supported in Acra CE
	return nil, ErrNotImplementedV1
}

// OpenKeyStoreForImport opens a key store suitable for import operations.
func (*DefaultKeyStoreFactory) OpenKeyStoreForImport(params *CommandLineParams) (api.MutableKeyStore, error) {
	if filesystemV2.IsKeyDirectory(params.KeyDir) {
		return openKeyStoreV2(params)
	}
	// Not supported in Acra CE
	return nil, ErrNotImplementedV1
}

func openKeyStoreV1(params *CommandLineParams) (*filesystemV1.KeyStore, error) {
	symmetricKey, err := keystoreV1.GetMasterKeyFromEnvironment()
	if err != nil {
		log.WithError(err).Errorln("Cannot read master keys from environment")
		return nil, err
	}
	scellEncryptor, err := keystoreV1.NewSCellKeyEncryptor(symmetricKey)
	if err != nil {
		log.WithError(err).Errorln("Failed to initialize Secure Cell encryptor")
		return nil, err
	}
	var store *filesystemV1.KeyStore
	if params.KeyDir != params.KeyDirPublic {
		store, err = filesystemV1.NewFilesystemKeyStoreTwoPath(params.KeyDir, params.KeyDirPublic, scellEncryptor)
	} else {
		store, err = filesystemV1.NewFilesystemKeyStore(params.KeyDir, scellEncryptor)
	}
	if err != nil {
		log.WithError(err).Errorln("Failed to initialize key")
		return nil, err
	}
	return store, nil
}

func openKeyStoreV2(params *CommandLineParams) (*keystoreV2.ServerKeyStore, error) {
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
	keyDir, err := filesystemV2.OpenDirectoryRW(params.KeyDir, suite)
	if err != nil {
		log.WithError(err).WithField("path", params.KeyDir).Error("Cannot open key directory")
		return nil, err
	}
	return keystoreV2.NewServerKeyStore(keyDir), nil
}
