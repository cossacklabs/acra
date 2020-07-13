/*
Copyright 2016, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package main is entry point for AcraKeymaker utility. AcraKeymaker generates key pairs for transport and storage keys
// and writes it to default keys folder. Private keys are encrypted using Themis SecureCell and ACRA_MASTER_KEY,
// public keys are plaintext.
//
// https://github.com/cossacklabs/acra/wiki/Key-Management
package main

import (
	"flag"
	"io/ioutil"
	"os"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

// Constants used by AcraKeymaker
var (
	// defaultConfigPath relative path to config which will be parsed as default
	defaultConfigPath = utils.GetConfigPathByName("acra-keymaker")
	serviceName       = "acra-keymaker"
)

func main() {
	clientID := flag.String("client_id", "client", "Client ID")
	acraConnector := flag.Bool("generate_acraconnector_keys", false, "Create keypair for AcraConnector only")
	acraServer := flag.Bool("generate_acraserver_keys", false, "Create keypair for AcraServer only")
	acraTranslator := flag.Bool("generate_acratranslator_keys", false, "Create keypair for AcraTranslator only")
	dataKeys := flag.Bool("generate_acrawriter_keys", false, "Create keypair for data encryption/decryption")
	basicauth := flag.Bool("generate_acrawebconfig_keys", false, "Create symmetric key for AcraWebconfig's basic auth db")
	outputDir := flag.String("keys_output_dir", keystore.DefaultKeyDirShort, "Folder where will be saved keys")
	outputPublicKey := flag.String("keys_public_output_dir", keystore.DefaultKeyDirShort, "Folder where will be saved public key")
	masterKey := flag.String("generate_master_key", "", "Generate new random master key and save to file")
	keystoreVersion := flag.String("keystore", "", "set key store format: v1 (current), v2 (new)")

	logging.SetLogLevel(logging.LogVerbose)

	err := cmd.Parse(defaultConfigPath, serviceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}

	cmd.ValidateClientID(*clientID)

	if *masterKey != "" {
		newKey, err := keystore.GenerateSymmetricKey()
		if err != nil {
			panic(err)
		}
		if err := ioutil.WriteFile(*masterKey, newKey, 0600); err != nil {
			panic(err)
		}
		os.Exit(0)
	}

	var store keystore.KeyMaking
	// If the key store already exists, detect its version automatically and allow to not specify it.
	if *keystoreVersion == "" {
		if fi, err := os.Stat(*outputDir); err == nil && fi.IsDir() {
			if filesystemV2.IsKeyDirectory(*outputDir) {
				*keystoreVersion = "v2"
			} else {
				*keystoreVersion = "v1"
			}
		}
	}
	switch *keystoreVersion {
	case "v1":
		store = openKeyStoreV1(*outputDir, *outputPublicKey)
	case "v2":
		store = openKeyStoreV2(*outputDir)
	case "":
		log.Errorf("Key store version is required: --keystore={v1|v2}")
		os.Exit(1)
	default:
		log.Errorf("Unknown --keystore option: %v", *keystoreVersion)
		os.Exit(1)
	}

	if *acraConnector {
		err = store.GenerateConnectorKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}
	}
	if *acraServer {
		err = store.GenerateServerKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}
	}
	if *acraTranslator {
		err = store.GenerateTranslatorKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}
	}
	if *dataKeys {
		err = store.GenerateDataEncryptionKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}
	}
	if *basicauth {
		_, err = store.GetAuthKey(true)
		if err != nil {
			panic(err)
		}
	}
	if !(*acraConnector || *acraServer || *acraTranslator || *dataKeys || *basicauth) {
		err = store.GenerateConnectorKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}

		err = store.GenerateServerKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}

		err = store.GenerateTranslatorKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}

		err = store.GenerateDataEncryptionKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}
	}
}

func openKeyStoreV1(outputDir, outputPublicKey string) keystore.KeyMaking {
	symmetricKey, err := keystore.GetMasterKeyFromEnvironment()
	if err != nil {
		if err == keystore.ErrEmptyMasterKey {
			log.Infof("You must pass master key via %v environment variable", keystore.AcraMasterKeyVarName)
			os.Exit(1)
		}
		log.WithError(err).Errorln("Can't load master key")
		os.Exit(1)
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(symmetricKey)
	if err != nil {
		log.WithError(err).Errorln("Can't init scell encryptor")
		os.Exit(1)
	}
	var store keystore.KeyMaking
	if outputPublicKey != outputDir {
		store, err = filesystem.NewFilesystemKeyStoreTwoPath(outputDir, outputPublicKey, scellEncryptor)
	} else {
		store, err = filesystem.NewFilesystemKeyStore(outputDir, scellEncryptor)
	}
	if err != nil {
		log.WithError(err).Errorln("Can't init key store")
		os.Exit(1)
	}
	return store
}

func openKeyStoreV2(keyDirPath string) keystore.KeyMaking {
	encryption, signature, err := keystoreV2.GetMasterKeysFromEnvironment()
	if err != nil {
		log.WithError(err).Error("cannot read master keys from environment")
		os.Exit(1)
	}
	suite, err := keystoreV2.NewSCellSuite(encryption, signature)
	if err != nil {
		log.WithError(err).Error("failed to initialize Secure Cell crypto suite")
		os.Exit(1)
	}
	keyDir, err := filesystemV2.OpenDirectoryRW(keyDirPath, suite)
	if err != nil {
		log.WithError(err).WithField("path", keyDirPath).Error("cannot open key directory")
		os.Exit(1)
	}
	return keystoreV2.NewServerKeyStore(keyDir)
}
