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

// Package keys defines reusable business logic of `acra-keys` utility.
package keys

import (
	"fmt"
	"os"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

func warnKeystoreV2Only(command string) {
	log.Error(fmt.Sprintf("\"%s\" is not implemented for key store v1", command))
	log.Info("You can convert key store v1 into v2 with \"acra-keys migrate\"")
	// TODO(ilammy, 2020-05-19): production documentation does not describe migration yet
	log.Info("Read more: https://docs.cossacklabs.com/pages/documentation-acra/#key-management")
}

// ListKeysCommand implements the "list" command.
func ListKeysCommand(params ListKeysParams, keyStore keystore.ServerKeyStore) {
	keyDescriptions, err := keyStore.ListKeys()
	if err != nil {
		if err == ErrNotImplementedV1 {
			warnKeystoreV2Only(CmdListKeys)
		}
		log.WithError(err).Fatal("Failed to read key list")
	}

	err = PrintKeys(keyDescriptions, os.Stdout, params)
	if err != nil {
		log.WithError(err).Fatal("Failed to print key list")
	}
}

// ExportKeysCommand implements the "export" command.
func ExportKeysCommand(params ExportKeysParams, keyStore api.KeyStore) {
	encryptionKeyData, cryptosuite, err := PrepareExportEncryptionKeys()
	if err != nil {
		log.WithError(err).Fatal("Failed to prepare encryption keys")
	}
	defer utils.ZeroizeSymmetricKey(encryptionKeyData)

	exportedData, err := ExportKeys(keyStore, cryptosuite, params)
	if err != nil {
		log.WithError(err).Fatal("Failed to export keys")
	}

	err = WriteExportedData(exportedData, encryptionKeyData, params)
	if err != nil {
		log.WithError(err).Fatal("Failed to write exported data")
	}

	log.Infof("Exported key data is encrypted and saved here: %s", params.ExportDataFile())
	log.Infof("New encryption keys for import generated here: %s", params.ExportKeysFile())
	log.Infof("DO NOT transport or store these files together")
	log.Infof("Import the keys into another key store like this:\n\tacra-keys import --key_bundle_file \"%s\" --key_bundle_secret \"%s\"", params.ExportDataFile(), params.ExportKeysFile())
}

// ImportKeysCommand implements the "import" command.
func ImportKeysCommand(params ImportKeysParams, keyStore api.MutableKeyStore) {
	exportedData, err := ReadExportedData(params)
	if err != nil {
		log.WithError(err).Fatal("Failed to read exported data")
	}

	cryptosuite, err := ReadImportEncryptionKeys(params)
	if err != nil {
		log.WithError(err).Fatal("Failed to prepare encryption keys")
	}

	descriptions, err := ImportKeys(exportedData, keyStore, cryptosuite, params)
	if err != nil {
		log.WithError(err).Fatal("Failed to import keys")
	}

	log.Infof("successfully imported %d keys", len(descriptions))

	err = PrintKeys(descriptions, os.Stdout, params)
	if err != nil {
		log.WithError(err).Fatal("Failed to print imported key list")
	}
}

// PrintKeyCommand implements the "read" command.
func PrintKeyCommand(params ReadKeyParams, keyStore keystore.ServerKeyStore) {
	keyBytes, err := ReadKeyBytes(params, keyStore)
	if err != nil {
		log.WithError(err).Fatal("Failed to read key")
	}
	defer utils.ZeroizeSymmetricKey(keyBytes)

	_, err = os.Stdout.Write(keyBytes)
	if err != nil {
		log.WithError(err).Fatal("Failed to write key")
	}
}

// DestroyKeyCommand implements the "destroy" command.
func DestroyKeyCommand(params DestroyKeyParams, keyStore keystore.KeyMaking) {
	err := DestroyKey(params, keyStore)
	if err != nil {
		log.WithError(err).Fatal("Failed to destroy key")
	}
}
