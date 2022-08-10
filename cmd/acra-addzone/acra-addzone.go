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

// Package main is entry point for AcraAddZone utility. AcraAddZone allows to generate Zone data (ID and public key)
// that should be used to create AcraStructs.
// Zones are the way to cryptographically compartmentalise records in an already-encrypted environment.
// Zones rely on different private keys on the server side. The idea behind Zones is very simple
// (yet quite specific to some use-cases): when we store sensitive data, it's frequently related to users /
// companies / some other binding entities. These entities could be described through some real-world identifiers,
// or (preferably) random identifiers, which have no computable relationship to the protected data.
// Acra uses this identifier to also identify, which key to use for decryption of a corresponding AcraStruct.
//
// https://github.com/cossacklabs/acra/wiki/Zones
// https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter#client-side-with-zones
package main

import (
	"flag"
	"fmt"
	baseKMS "github.com/cossacklabs/acra/keystore/kms/base"
	"os"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/keystore/keyloader/hashicorp"
	"github.com/cossacklabs/acra/keystore/keyloader/kms"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	filesystemBackendV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"

	log "github.com/sirupsen/logrus"
)

// Constants used by AcraAddZone util.
var (
	// defaultConfigPath relative path to config which will be parsed as default
	defaultConfigPath = utils.GetConfigPathByName("acra-addzone")
	serviceName       = "acra-addzone"
)

func main() {
	outputDir := flag.String("keys_output_dir", keystore.DefaultKeyDirShort, "Folder where will be saved generated zone keys")
	flag.Bool("fs_keystore_enable", true, "Use filesystem keystore (deprecated, ignored)")

	hashicorp.RegisterVaultCLIParameters()
	kms.RegisterCLIParameters()
	keyloader.RegisterCLIParameters()
	cmd.RegisterRedisKeyStoreParameters()
	verbose := flag.Bool("v", false, "Log to stderr all INFO, WARNING and ERROR logs")

	err := cmd.Parse(defaultConfigPath, serviceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}
	if *verbose {
		log.Infof("Enabling VERBOSE log level")
		logging.SetLogLevel(logging.LogDebug)
	} else {
		log.Infof("Disabling future logs... Set -v to see logs")
		logging.SetLogLevel(logging.LogVerbose)
	}

	var keyStore keystore.KeyMaking
	if filesystemV2.IsKeyDirectory(*outputDir) {
		keyStore = openKeyStoreV2(*outputDir)
	} else {
		keyStore = openKeyStoreV1(*outputDir)
	}

	id, publicKey, err := keyStore.GenerateZoneKey()
	if err != nil {
		log.WithError(err).Errorln("Can't add zone")
		os.Exit(1)
	}
	if err := keyStore.GenerateZoneIDSymmetricKey(id); err != nil {
		log.WithError(err).Errorln("Can't generate symmetric key")
		os.Exit(1)
	}
	log.Debugln("Generated symmetric key")

	json, err := zone.DataToJSON(id, &keys.PublicKey{Value: publicKey})
	if err != nil {
		log.WithError(err).Errorln("Can't encode to json")
		os.Exit(1)
	}
	fmt.Println(string(json))
}

func openKeyStoreV1(output string) keystore.KeyMaking {
	var keyStoreEncryptor keystore.KeyEncryptor

	var keyLoaderParams = keyloader.GetCLIParameters()
	keyStoreEncryptor, err := keyloader.CreateKeyEncryptor(keyloader.GetCLIParameters().KeystoreEncryptorType)
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore KeyEncryptor")
		os.Exit(1)
	}

	keyStoreBuilder := filesystem.NewCustomFilesystemKeyStore()
	keyStoreBuilder.KeyDirectory(output)
	keyStoreBuilder.Encryptor(keyStoreEncryptor)
	redis := cmd.GetRedisParameters()
	if redis.KeysConfigured() {
		keyStorage, err := filesystem.NewRedisStorage(redis.HostPort, redis.Password, redis.DBKeys, nil)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
				Errorln("Can't initialize Redis client")
			os.Exit(1)
		}
		keyStoreBuilder.Storage(keyStorage)
	}
	keyStore, err := keyStoreBuilder.Build()
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore")
		os.Exit(1)
	}

	if keyLoaderParams.KeystoreEncryptorType == keyloader.KeystoreStrategyKMSPerClient {
		keyManager, _ := kms.NewKeyManager(kms.GetCLIParameters())
		return baseKMS.NewKeyMakingWrapper(keyStore, keyManager)
	}

	return keyStore
}

func openKeyStoreV2(keyDirPath string) keystore.KeyMaking {
	keyStoreSuite, err := keyloader.CreateKeyEncryptorSuite(keyloader.GetCLIParameters().KeystoreEncryptorType)
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore keyStoreSuite")
		os.Exit(1)
	}
	var backend filesystemBackendV2.Backend
	redis := cmd.GetRedisParameters()
	if redis.KeysConfigured() {
		config := &filesystemBackendV2.RedisConfig{
			RootDir: keyDirPath,
			Options: redis.KeysOptions(),
		}
		backend, err = filesystemBackendV2.OpenRedisBackend(config)
		if err != nil {
			log.WithError(err).Error("Cannot connect to Redis keystore")
			os.Exit(1)
		}
	} else {
		backend, err = filesystemBackendV2.OpenDirectoryBackend(keyDirPath)
		if err != nil {
			log.WithError(err).Error("Cannot open key directory")
			os.Exit(1)
		}
	}
	keyDirectory, err := filesystemV2.CustomKeyStore(backend, keyStoreSuite)
	if err != nil {
		log.WithError(err).Error("Failed to initialize key directory")
		os.Exit(1)
	}
	return keystoreV2.NewServerKeyStore(keyDirectory)
}
