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
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

// Constants used by AcraPoisonRecordsMaker
var (
	// defaultConfigPath relative path to config which will be parsed as default
	defaultConfigPath = utils.GetConfigPathByName("acra-poisonrecordmaker")
	serviceName       = "acra-poisonrecordmaker"
)

func main() {
	keysDir := flag.String("keys_dir", keystore.DefaultKeyDirShort, "Folder from which will be loaded keys")
	keystoreOpts := flag.String("keystore", "", "force Key Store format: v1 (current), v2 (experimental)")
	dataLength := flag.Int("data_length", poison.UseDefaultDataLength, fmt.Sprintf("Length of random data for data block in acrastruct. -1 is random in range 1..%v", poison.DefaultDataLength))

	logging.SetLogLevel(logging.LogDiscard)

	err := cmd.Parse(defaultConfigPath, serviceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("can't parse args")
		os.Exit(1)
	}

	var store keystore.PoisonKeyStore
	if *keystoreOpts == "" {
		if filesystemV2.IsKeyDirectory(*keysDir) {
			*keystoreOpts = "v2"
		} else {
			*keystoreOpts = "v1"
		}
	}
	switch *keystoreOpts {
	case "v1":
		store = openKeyStoreV1(*keysDir)
	case "v2":
		store = openKeyStoreV2(*keysDir)
	default:
		log.Errorf("unknown keystore option: %v", *keystoreOpts)
		os.Exit(1)
	}

	poisonRecord, err := poison.CreatePoisonRecord(store, *dataLength)
	if err != nil {
		log.WithError(err).Errorln("can't create poison record")
		os.Exit(1)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(poisonRecord))
}

func openKeyStoreV1(keysDir string) keystore.PoisonKeyStore {
	masterKey, err := keystore.GetMasterKeyFromEnvironment()
	if err != nil {
		log.WithError(err).Errorln("can't load master key")
		os.Exit(1)
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithError(err).Errorln("can't init scell encryptor")
		os.Exit(1)
	}
	store, err := filesystem.NewFilesystemKeyStore(keysDir, scellEncryptor)
	if err != nil {
		log.WithError(err).Errorln("can't initialize key store")
		os.Exit(1)
	}
	return store
}

func openKeyStoreV2(keyDirPath string) keystore.PoisonKeyStore {
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
