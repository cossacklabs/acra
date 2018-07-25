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
	keysDir := flag.String("keys_dir", keystore.DEFAULT_KEY_DIR_SHORT, "Folder from which will be loaded keys")
	dataLength := flag.Int("data_length", poison.DEFAULT_DATA_LENGTH, fmt.Sprintf("Length of random data for data block in acrastruct. -1 is random in range 1..%v", poison.MAX_DATA_LENGTH))

	logging.SetLogLevel(logging.LOG_DISCARD)

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
