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

	"github.com/cossacklabs/acra/keystore"
	keystoreV1 "github.com/cossacklabs/acra/keystore"
	filesystemV1 "github.com/cossacklabs/acra/keystore/filesystem"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	log "github.com/sirupsen/logrus"
)

// KeyStoreFactory should return one of those errors when it is not able to construct requested key store.
var (
	ErrNotImplementedV1 = errors.New("not implemented for keystore v1")
)

// KeyStoreParameters are parameters for DefaultKeyStoreFactory.
type KeyStoreParameters interface {
	KeyDir() string
	KeyDirPublic() string
}

// CommonKeyStoreParameters is a mix-in of command line parameters for key store construction.
type CommonKeyStoreParameters struct {
	keyDir       string
	keyDirPublic string
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

// Register registers key store flags with the given flag set.
func (p *CommonKeyStoreParameters) Register(flags *flag.FlagSet) {
	p.RegisterPrefixed(flags, DefaultKeyDirectory, "", "")
}

// RegisterPrefixed registers key store flags with the given flag set, using given prefix and description.
func (p *CommonKeyStoreParameters) RegisterPrefixed(flags *flag.FlagSet, defaultKeysDir, flagPrefix, descriptionSuffix string) {
	if descriptionSuffix != "" {
		descriptionSuffix = " " + descriptionSuffix
	}
	flags.StringVar(&p.keyDir, flagPrefix+"keys_dir", defaultKeysDir, "path to key directory"+descriptionSuffix)
	flags.StringVar(&p.keyDirPublic, flagPrefix+"keys_dir_public", "", "path to key directory for public keys"+descriptionSuffix)
}

// OpenKeyStoreForReading opens a key store suitable for reading keys.
func OpenKeyStoreForReading(params KeyStoreParameters) (keystore.ServerKeyStore, error) {
	if filesystemV2.IsKeyDirectory(params.KeyDir()) {
		return openKeyStoreV2(params)
	}
	return openKeyStoreV1(params)
}

// OpenKeyStoreForWriting opens a key store suitable for modifications.
func OpenKeyStoreForWriting(params KeyStoreParameters) (keystore.KeyMaking, error) {
	if filesystemV2.IsKeyDirectory(params.KeyDir()) {
		return openKeyStoreV2(params)
	}
	return openKeyStoreV1(params)
}

// OpenKeyStoreForExport opens a key store suitable for export operations.
func OpenKeyStoreForExport(params KeyStoreParameters) (api.KeyStore, error) {
	if filesystemV2.IsKeyDirectory(params.KeyDir()) {
		return openKeyStoreV2(params)
	}
	// Not supported in Acra CE
	return nil, ErrNotImplementedV1
}

// OpenKeyStoreForImport opens a key store suitable for import operations.
func OpenKeyStoreForImport(params KeyStoreParameters) (api.MutableKeyStore, error) {
	if filesystemV2.IsKeyDirectory(params.KeyDir()) {
		return openKeyStoreV2(params)
	}
	// Not supported in Acra CE
	return nil, ErrNotImplementedV1
}

func openKeyStoreV1(params KeyStoreParameters) (*filesystemV1.KeyStore, error) {
	symmetricKey, err := keystoreV1.GetMasterKeyFromEnvironment()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master key")
		return nil, err
	}
	scellEncryptor, err := keystoreV1.NewSCellKeyEncryptor(symmetricKey)
	if err != nil {
		log.WithError(err).Errorln("Failed to initialize Secure Cell encryptor")
		return nil, err
	}
	var store *filesystemV1.KeyStore
	keyDir := params.KeyDir()
	keyDirPublic := params.KeyDirPublic()
	if keyDir != keyDirPublic {
		store, err = filesystemV1.NewFilesystemKeyStoreTwoPath(keyDir, keyDirPublic, scellEncryptor)
	} else {
		store, err = filesystemV1.NewFilesystemKeyStore(keyDir, scellEncryptor)
	}
	if err != nil {
		log.WithError(err).Errorln("Failed to initialize key")
		return nil, err
	}
	return store, nil
}

func openKeyStoreV2(params KeyStoreParameters) (*keystoreV2.ServerKeyStore, error) {
	encryption, signature, err := keystoreV2.GetMasterKeysFromEnvironment()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master key")
		return nil, err
	}
	suite, err := keystoreV2.NewSCellSuite(encryption, signature)
	if err != nil {
		log.WithError(err).Error("Failed to initialize Secure Cell crypto suite")
		return nil, err
	}
	path := params.KeyDir()
	keyDir, err := filesystemV2.OpenDirectoryRW(path, suite)
	if err != nil {
		log.WithError(err).WithField("path", path).Error("Cannot open key directory")
		return nil, err
	}
	return keystoreV2.NewServerKeyStore(keyDir), nil
}
