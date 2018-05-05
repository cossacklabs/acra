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
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
)

// DEFAULT_CONFIG_PATH relative path to config which will be parsed as default
var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName("acra-keymaker")

func main() {
	clientId := flag.String("client_id", "client", "Client id")
	acraConnector := flag.Bool("acra-connector", false, "Create keypair for AcraConnector only")
	acraserver := flag.Bool("acra-server", false, "Create keypair for AcraServer only")
	dataKeys := flag.Bool("storage", false, "Create keypair for data encryption/decryption")
	basicauth := flag.Bool("basicauth", false, "Create symmetric key for AcraWebconfig's basic auth db")
	outputDir := flag.String("output", keystore.DEFAULT_KEY_DIR_SHORT, "Folder where will be saved keys")
	outputPublicKey := flag.String("output_public", keystore.DEFAULT_KEY_DIR_SHORT, "Folder where will be saved public key")
	masterKey := flag.String("master_key", "", "Generate new random master key and save to file")

	logging.SetLogLevel(logging.LOG_VERBOSE)

	err := cmd.Parse(DEFAULT_CONFIG_PATH)
	if err != nil {
		log.WithError(err).Errorln("can't parse args")
		os.Exit(1)
	}

	cmd.ValidateClientId(*clientId)

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

	symmetricKey, err := keystore.GetMasterKeyFromEnvironment()
	if err != nil {
		if err == keystore.ErrEmptyMasterKey {
			log.Infof("You must pass master key via %v environment variable", keystore.ACRA_MASTER_KEY_VAR_NAME)
			os.Exit(1)
		}
		log.WithError(err).Errorln("can't load master key")
		os.Exit(1)
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(symmetricKey)
	if err != nil {
		log.WithError(err).Errorln("can't init scell encryptor")
		os.Exit(1)
	}
	var store keystore.KeyStore
	if *outputPublicKey != *outputDir {
		store, err = keystore.NewFilesystemKeyStoreTwoPath(*outputDir, *outputPublicKey, scellEncryptor)
	} else {
		store, err = keystore.NewFilesystemKeyStore(*outputDir, scellEncryptor)
	}
	if err != nil {
		panic(err)
	}

	if *acraConnector {
		err = store.GenerateConnectorKeys([]byte(*clientId))
		if err != nil {
			panic(err)
		}
	} else if *acraserver {
		err = store.GenerateServerKeys([]byte(*clientId))
		if err != nil {
			panic(err)
		}
	} else if *dataKeys {
		err = store.GenerateDataEncryptionKeys([]byte(*clientId))
		if err != nil {
			panic(err)
		}
	} else if *basicauth {
		_, err = store.GetAuthKey(true)
		if err != nil {
			panic(err)
		}
	} else {
		err = store.GenerateConnectorKeys([]byte(*clientId))
		if err != nil {
			panic(err)
		}

		err = store.GenerateServerKeys([]byte(*clientId))
		if err != nil {
			panic(err)
		}

		err = store.GenerateDataEncryptionKeys([]byte(*clientId))
		if err != nil {
			panic(err)
		}
	}
}
