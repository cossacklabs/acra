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
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/cossacklabs/acra/keystore"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

// ExportKeyPerm is file permissions required for exported key data.
const ExportKeyPerm = os.FileMode(0600)

// Key export errors:
var (
	ErrIncorrectPerm = errors.New("incorrect output file permissions")
)

type serializedKeys struct {
	Encryption []byte `json:"encryption"`
	Signature  []byte `json:"signature"`
}

// PrepareExportEncryptionKeys generates new ephemeral keys for key export operation.
func PrepareExportEncryptionKeys() ([]byte, *crypto.KeyStoreSuite, error) {
	encryptionKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		log.WithError(err).Debug("Failed to generate symmetric key")
		return nil, nil, err
	}

	signatureKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		log.WithError(err).Debug("Failed to generate symmetric key")
		return nil, nil, err
	}

	serializedKeys, err := json.Marshal(&serializedKeys{Encryption: encryptionKey, Signature: signatureKey})
	if err != nil {
		log.WithError(err).Debug("Failed to serialize keys in JSON")
		return nil, nil, err
	}

	// We do not zeroize the keys since a) they are stored by reference in the cryptosuite,
	// b) they have not been used to encrypt anything yet.
	cryptosuite, err := crypto.NewSCellSuite(encryptionKey, signatureKey)
	if err != nil {
		log.WithError(err).Debug("Failed to setup cryptosuite")
		return nil, nil, err
	}

	return serializedKeys, cryptosuite, nil
}

// ReadImportEncryptionKeys reads ephemeral keys for key import operation.
func ReadImportEncryptionKeys(params *CommandLineParams) (*crypto.KeyStoreSuite, error) {
	importEncryptionKeyData, err := ioutil.ReadFile(params.ExportKeysFile)
	if err != nil {
		log.WithField("path", params.ExportKeysFile).WithError(err).Debug("Failed to read key file")
		return nil, err
	}
	defer utils.ZeroizeSymmetricKey(importEncryptionKeyData)

	var importEncryptionKeys serializedKeys
	err = json.Unmarshal(importEncryptionKeyData, &importEncryptionKeys)
	if err != nil {
		log.WithField("path", params.ExportKeysFile).WithError(err).Debug("Failed to parse key file content")
		return nil, err
	}

	cryptosuite, err := crypto.NewSCellSuite(importEncryptionKeys.Encryption, importEncryptionKeys.Signature)
	if err != nil {
		log.WithField("path", params.ExportKeysFile).WithError(err).Debug("Failed to initialize cryptosuite")
		return nil, err
	}

	return cryptosuite, nil
}

// ExportKeys exports requested key rings.
func ExportKeys(keyStore *keystoreV2.ServerKeyStore, cryptosuite *crypto.KeyStoreSuite, params *CommandLineParams) (exportedData []byte, err error) {
	exportedIDs := params.ExportIDs
	if params.ExportAll {
		exportedIDs, err = keyStore.ListKeyRings()
		if err != nil {
			log.WithError(err).Debug("Failed to list available keys")
			return nil, err
		}
	}

	exportedData, err = keyStore.ExportKeyRings(exportedIDs, cryptosuite)
	if err != nil {
		log.WithError(err).Debug("Failed to export key rings")
		return nil, err
	}
	return exportedData, nil
}

// ImportKeys imports available key rings.
func ImportKeys(exportedData []byte, keyStore *keystoreV2.ServerKeyStore, cryptosuite *crypto.KeyStoreSuite, params *CommandLineParams) error {
	return keyStore.ImportKeyRings(exportedData, cryptosuite, nil)
}

// WriteExportedData saves exported key data and ephemeral keys into designated files.
func WriteExportedData(data, keys []byte, params *CommandLineParams) error {
	err := writeFileWithMode(data, params.ExportDataFile, ExportKeyPerm)
	if err != nil {
		return err
	}
	err = writeFileWithMode(keys, params.ExportKeysFile, ExportKeyPerm)
	if err != nil {
		return err
	}
	return nil
}

// ReadExportedData reads exported key data from designated file.
func ReadExportedData(params *CommandLineParams) ([]byte, error) {
	exportedKeyData, err := ioutil.ReadFile(params.ExportDataFile)
	if err != nil {
		log.WithField("path", params.ExportDataFile).WithError(err).Debug("Failed to read data file")
		return nil, err
	}
	return exportedKeyData, nil
}

func writeFileWithMode(data []byte, path string, perm os.FileMode) (err error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		log.WithField("path", path).WithError(err).Debug("Failed to open file")
		return err
	}
	defer func() {
		if err2 := file.Close(); err2 != nil {
			log.WithField("path", path).WithError(err2).Debug("Failed to close file")
			if err != nil {
				err = err2
			}
		}
	}()

	fi, err := file.Stat()
	if err != nil {
		log.WithField("path", path).WithError(err).Debug("Failed to stat file")
		return err
	}
	if fi.Mode().Perm() != ExportKeyPerm {
		log.WithField("path", path).WithField("expected", ExportKeyPerm).WithField("actual", fi.Mode().Perm()).
			Error("Incorrect output file permissions")
		return ErrIncorrectPerm
	}

	_, err = utils.WriteFull(data, file)
	return err
}
