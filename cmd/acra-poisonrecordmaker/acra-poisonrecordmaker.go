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
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
	"os"
)

// Constants used by AcraPoisonRecordsMaker
var (
	// DEFAULT_CONFIG_PATH relative path to config which will be parsed as default
	DEFAULT_CONFIG_PATH = utils.GetConfigPathByName("acra-poisonrecordmaker")
	SERVICE_NAME        = "acra-poisonrecordmaker"
)

func main() {
	keysDir := flag.String("keys_dir", keystore.DefaultKeyDirShort, "Folder from which will be loaded keys")
	dataLength := flag.Int("data_length", poison.UseDefaultDataLength, fmt.Sprintf("Length of random data for data block in acrastruct. -1 is random in range 1..%v", poison.DefaultDataLength))

	logging.SetLogLevel(logging.LogDiscard)

	err := cmd.Parse(DEFAULT_CONFIG_PATH, SERVICE_NAME)
	if err != nil {
		log.WithError(err).Errorln("can't parse args")
		os.Exit(1)
	}

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
	store, err := filesystem.NewFilesystemKeyStore(*keysDir, scellEncryptor)
	if err != nil {
		log.WithError(err).Errorln("can't initialize key store")
		os.Exit(1)
	}
	poisonRecord, err := poison.CreatePoisonRecord(store, *dataLength)
	if err != nil {
		log.WithError(err).Errorln("can't create poison record")
		os.Exit(1)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(poisonRecord))
}
