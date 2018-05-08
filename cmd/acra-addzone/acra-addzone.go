// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"flag"
	"fmt"
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
	"os"
)

// DEFAULT_CONFIG_PATH relative path to config which will be parsed as default
var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName("acra-addzone")
var SERVICE_NAME = "acra_addzone"

func main() {
	outputDir := flag.String("keys_output_dir", keystore.DEFAULT_KEY_DIR_SHORT, "Folder where will be saved generated zone keys")
	fsKeystore := flag.Bool("fs_keystore_enable", true, "Use filesystem key store")

	logging.SetLogLevel(logging.LOG_VERBOSE)

	err := cmd.Parse(DEFAULT_CONFIG_PATH, SERVICE_NAME)
	if err != nil {
		log.WithError(err).Errorln("can't parse args")
		os.Exit(1)
	}
	//LoadFromConfig(DEFAULT_CONFIG_PATH)
	//iniflags.Parse()

	output, err := utils.AbsPath(*outputDir)
	if err != nil {
		log.WithError(err).Errorln("can't get absolute path for output dir")
		os.Exit(1)
	}
	var keyStore keystore.KeyStore
	if *fsKeystore {
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
		keyStore, err = keystore.NewFilesystemKeyStore(output, scellEncryptor)
		if err != nil {
			log.WithError(err).Errorln("can't create key store")
			os.Exit(1)
		}
	} else {
		panic("No more supported keystores")
	}
	id, publicKey, err := keyStore.GenerateZoneKey()
	if err != nil {
		log.WithError(err).Errorln("can't add zone")
		os.Exit(1)
	}
	json, err := zone.ZoneDataToJson(id, &keys.PublicKey{Value: publicKey})
	if err != nil {
		log.WithError(err).Errorln("can't encode to json")
		os.Exit(1)
	}
	fmt.Println(string(json))
}
