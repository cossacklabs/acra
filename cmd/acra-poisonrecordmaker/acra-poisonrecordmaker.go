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

// Package main is entry point for AcraPoisonRecordsMaker utility. AcraPoisonRecordsMaker generates poison record with
// desired length and outputs it to console. Poison records are the records specifically designed and crafted
// in such a way that they wouldn't be queried by a user under normal circumstances. Yet poison records will be
// included in the outputs of SELECT * requests. Upon passing AcraServer, they will inform it of untypical behaviour.
// The goal of using poison records is simple — to detect adversaries trying to download full tables / full database
// from the application server or trying to run full scans in their injected queries.
//
// https://github.com/cossacklabs/acra/wiki/Intrusion-detection
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/keystore/keyloader/kms"
	"github.com/cossacklabs/acra/keystore/kms/base"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	filesystemBackendV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/utils/args"

	log "github.com/sirupsen/logrus"
)

// Constants used by AcraPoisonRecordsMaker
var (
	// defaultConfigPath relative path to config which will be parsed as default
	defaultConfigPath = utils.GetConfigPathByName("acra-poisonrecordmaker")
	serviceName       = "acra-poisonrecordmaker"
)

// Types of crypto envelope of poison records
const (
	RecordTypeAcraStruct = "acrastruct"
	RecordTypeAcraBlock  = "acrablock"
)

func registerFlags(flagSet *flag.FlagSet) {
	flagSet.String("keys_dir", keystore.DefaultKeyDirShort, "Folder from which will be loaded keys")
	flagSet.Int("data_length", poison.UseDefaultDataLength, fmt.Sprintf("Length of random data for data block in acrastruct. -1 is random in range 1..%v", poison.DefaultDataLength))
	flagSet.String("type", RecordTypeAcraStruct, fmt.Sprintf("Type of poison record: \"%s\" | \"%s\"\n", RecordTypeAcraStruct, RecordTypeAcraBlock))

	network.RegisterTLSBaseArgs(flagSet)
	keyloader.RegisterKeyStoreStrategyParameters()
}

func main() {
	logging.SetLogLevel(logging.LogDiscard)
	registerFlags(flag.CommandLine)

	if err := cmd.ParseFlags(flag.CommandLine, os.Args[1:]); err != nil {
		if err == cmd.ErrDumpRequested {
			cmd.DumpConfig(defaultConfigPath, serviceName, true)
			os.Exit(0)
		}

		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}

	serviceConfig, err := cmd.ParseConfig(defaultConfigPath, serviceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse config")
		os.Exit(1)
	}

	paramsExtractor := args.NewServiceExtractor(flag.CommandLine, serviceConfig)

	keysDir := paramsExtractor.GetString("keys_dir", "")
	dataLength := paramsExtractor.GetInt("data_length", "")
	recordType := paramsExtractor.GetString("type", "")

	var store keystore.PoisonKeyStorageAndGenerator
	if filesystemV2.IsKeyDirectory(keysDir, paramsExtractor) {
		store = openKeyStoreV2(keysDir, paramsExtractor)
	} else {
		store = openKeyStoreV1(keysDir, paramsExtractor)
	}
	var poisonRecord []byte
	switch recordType {
	case RecordTypeAcraStruct:
		poisonRecord, err = poison.CreatePoisonRecord(store, dataLength)
	case RecordTypeAcraBlock:
		poisonRecord, err = poison.CreateSymmetricPoisonRecord(store, dataLength)
	default:
		log.Errorf("Incorrect type of record. Should be used \"%s\" or \"%s\"\n", RecordTypeAcraStruct, RecordTypeAcraBlock)
		os.Exit(1)
	}
	if err != nil {
		log.WithError(err).Errorln("Can't create poison record")
		os.Exit(1)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(poisonRecord))
}

func openKeyStoreV1(output string, extractor *args.ServiceExtractor) keystore.PoisonKeyStorageAndGenerator {
	var keyStoreEncryptor keystore.KeyEncryptor

	keyStoreEncryptor, err := keyloader.CreateKeyEncryptor(extractor, "")
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore KeyEncryptor")
		os.Exit(1)
	}

	keyStoreBuilder := filesystem.NewCustomFilesystemKeyStore()
	keyStoreBuilder.KeyDirectory(output)
	keyStoreBuilder.Encryptor(keyStoreEncryptor)
	if redis := cmd.ParseRedisCLIParameters(extractor); redis.KeysConfigured() {
		redisOptions, err := redis.KeysOptions(extractor)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
				Errorln("Can't get Redis options")
			os.Exit(1)
		}
		keyStorage, err := filesystem.NewRedisStorage(redis.HostPort, redis.Password, redis.DBKeys, redisOptions.TLSConfig)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
				Errorln("Can't initialize Redis client")
			os.Exit(1)
		}
		keyStoreBuilder.Storage(keyStorage)
	}
	keyStoreV1, err := keyStoreBuilder.Build()
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore")
		os.Exit(1)
	}

	if keyLoaderParams := keyloader.ParseCLIOptions(extractor); keyLoaderParams.KeystoreEncryptorType == keyloader.KeystoreStrategyKMSPerClient {
		keyManager, _ := kms.NewKeyManager(kms.ParseCLIParameters(extractor))
		return base.NewKeyMakingWrapper(keyStoreV1, keyManager, kms.NewKMSPerClientKeyMapper())
	}
	return keyStoreV1
}

func openKeyStoreV2(keyDirPath string, extractor *args.ServiceExtractor) keystore.PoisonKeyStorageAndGenerator {
	keyStoreSuite, err := keyloader.CreateKeyEncryptorSuite(extractor, "")
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore keyStoreSuite")
		os.Exit(1)
	}
	var backend filesystemBackendV2.Backend
	if redis := cmd.ParseRedisCLIParameters(extractor); redis.KeysConfigured() {
		redisOptions, err := redis.KeysOptions(extractor)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize Redis options")
			os.Exit(1)
		}
		config := &filesystemBackendV2.RedisConfig{
			RootDir: keyDirPath,
			Options: redisOptions,
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
