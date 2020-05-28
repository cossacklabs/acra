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

// Package main is entry point for `acra-keys` utility.
//
// It can access and maniplulate key stores:
//
//   - list keys
//   - read key data
//   - destroy keys
package main

import (
	"fmt"
	"os"

	"github.com/cossacklabs/acra/cmd/acra-keys/keys"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

func main() {
	keys.ParseParams()

	switch keys.Params.Command {
	case keys.CmdListKeys:
		listKeys(keys.Params)
	case keys.CmdExportKeys:
		exportKeys(keys.Params)
	case keys.CmdImportKeys:
		importKeys(keys.Params)
	case keys.CmdReadKey:
		printKey(keys.Params)
	case keys.CmdDestroyKey:
		destroyKey(keys.Params)
	}
}

func warnKeystoreV2Only(command string) {
	log.Error(fmt.Sprintf("\"%s\" is not implemented for key store v1 in Acra Community Edition", command))
	log.Info("You can convert key store v1 into v2 with \"acra-migrate-keys\"")
	// TODO(ilammy, 2020-05-19): production documentation does not describe migration yet
	log.Info("Read more: https://docs.cossacklabs.com/pages/documentation-acra/#key-management")
}

func listKeys(params *keys.CommandLineParams) {
	keyStore, err := keys.OpenKeyStoreForReading(params)
	if err != nil {
		log.WithError(err).Fatal("Failed to open key store")
	}

	keyDescriptions, err := keyStore.ListKeys()
	if err != nil {
		if err == keystore.ErrNotImplemented {
			warnKeystoreV2Only(keys.CmdListKeys)
		}
		log.WithError(err).Fatal("Failed to read key list")
	}

	err = keys.PrintKeys(keyDescriptions, os.Stdout, params)
	if err != nil {
		log.WithError(err).Fatal("Failed to print key list")
	}
}

func exportKeys(params *keys.CommandLineParams) {
	keyStore, err := keys.OpenKeyStoreForExportImport(params)
	if err != nil {
		if err == keystore.ErrNotImplemented {
			warnKeystoreV2Only(keys.CmdExportKeys)
		}
		log.WithError(err).Fatal("Failed to open key store")
	}

	encryptionKeyData, cryptosuite, err := keys.PrepareExportEncryptionKeys()
	if err != nil {
		log.WithError(err).Fatal("Failed to prepare encryption keys")
	}
	defer utils.ZeroizeSymmetricKey(encryptionKeyData)

	exportedData, err := keys.ExportKeys(keyStore, cryptosuite, params)
	if err != nil {
		log.WithError(err).Fatal("Failed to export keys")
	}

	err = keys.WriteExportedData(exportedData, encryptionKeyData, params)
	if err != nil {
		log.WithError(err).Fatal("Failed to write exported data")
	}

	log.Infof("Exported key data is encrypted and saved here: %s", params.ExportDataFile)
	log.Infof("New encryption keys for import generated here: %s", params.ExportKeysFile)
	log.Infof("DO NOT transport or store these files together")
	log.Infof("Import the keys into another key store like this:\n\tacra-keys import --data \"%s\" --keys \"%s\"", params.ExportDataFile, params.ExportKeysFile)
}

func importKeys(params *keys.CommandLineParams) {
	keyStore, err := keys.OpenKeyStoreForExportImport(params)
	if err != nil {
		if err == keystore.ErrNotImplemented {
			warnKeystoreV2Only(keys.CmdExportKeys)
		}
		log.WithError(err).Fatal("Failed to open key store")
	}

	exportedData, err := keys.ReadExportedData(params)
	if err != nil {
		log.WithError(err).Fatal("Failed to read exported data")
	}

	cryptosuite, err := keys.ReadImportEncryptionKeys(params)
	if err != nil {
		log.WithError(err).Fatal("Failed to prepare encryption keys")
	}

	err = keys.ImportKeys(exportedData, keyStore, cryptosuite, params)
	if err != nil {
		log.WithError(err).Fatal("Failed to import keys")
	}
}

func printKey(params *keys.CommandLineParams) {
	keyStore, err := keys.OpenKeyStoreForReading(params)
	if err != nil {
		log.WithError(err).Fatal("Failed to open key store")
	}

	keyBytes, err := keys.ReadKeyBytes(params, keyStore)
	if err != nil {
		log.WithError(err).Fatal("Failed to read key")
	}
	defer utils.ZeroizeSymmetricKey(keyBytes)

	_, err = os.Stdout.Write(keyBytes)
	if err != nil {
		log.WithError(err).Fatal("Failed to write key")
	}
}

func destroyKey(params *keys.CommandLineParams) {
	keyStore, err := keys.OpenKeyStoreForModification(params)
	if err != nil {
		log.WithError(err).Fatal("Failed to open key store")
	}

	err = keys.DestroyKey(params, keyStore)
	if err != nil {
		log.WithError(err).Fatal("Failed to destroy key")
	}
}
