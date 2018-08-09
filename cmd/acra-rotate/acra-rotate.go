/*
Copyright 2018, Cossack Labs Limited

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

// Package main is entry point for acra-rotate. Acra-rotate provide console utility to rotate private/zone keys and re-encrypt
// data stored in database or as files
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cossacklabs/acra/acra-writer"
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
)

// Constants used by AcraRotate
var (
	// DEFAULT_CONFIG_PATH relative path to config which will be parsed as default
	DEFAULT_CONFIG_PATH = utils.GetConfigPathByName("acra-rotate")
	SERVICE_NAME        = "acra-rotate"
)

func initKeyStore(dirPath string) (keystore.KeyStore, error) {
	absKeysDir, err := utils.AbsPath(dirPath)
	if err != nil {
		log.WithError(err).Errorln("Can't get absolute path for keys_dir")
		os.Exit(1)
	}
	masterKey, err := keystore.GetMasterKeyFromEnvironment()
	if err != nil {
		log.WithError(err).Errorln("Can't load master key")
		return nil, err
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithError(err).Errorln("Can't init scell encryptor")
		return nil, err
	}
	keystorage, err := filesystem.NewFilesystemKeyStore(absKeysDir, scellEncryptor)
	if err != nil {
		log.WithError(err).Errorln("Can't create key store")
		return nil, err
	}
	return keystorage, nil
}

func loadFileMap(path string) (ZoneIdFileMap, error) {
	configData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(configData)
}

// ZoneRotateData store new public key and paths of files that was rotated
type ZoneRotateData struct {
	NewPublicKey []byte
	FilePath     []string
}

// ZoneRotateResult store result of rotation
type ZoneRotateResult map[string]*ZoneRotateData

func rotateFiles(fileMap ZoneIdFileMap, keyStore keystore.KeyStore) (ZoneRotateResult, error) {
	output := ZoneRotateResult{}
	for zoneID, paths := range fileMap {
		logger := log.WithField("zone_id", zoneID)
		binZoneID := []byte(zoneID)
		privateKey, err := keyStore.GetZonePrivateKey(binZoneID)
		if err != nil {
			logger.WithError(err).Errorln("Can't load private key of zone")
			return nil, err
		}
		newPublicKey, err := keyStore.RotateZoneKey(binZoneID)
		if err != nil {
			logger.WithError(err).Errorln("Can't rotate zone key")
			return nil, err
		}
		result := &ZoneRotateData{NewPublicKey: newPublicKey}
		for _, path := range paths {
			logger = logger.WithField("filepath", path)
			result.FilePath = append(result.FilePath, path)
			acraStruct, err := ioutil.ReadFile(path)
			if err != nil {
				logger.WithError(err).Errorf("Can't read file %s", path)
				return nil, err
			}
			decrypted, err := base.DecryptAcrastruct(acraStruct, privateKey, binZoneID)
			if err != nil {
				logger.WithError(err).Errorln("Can't decrypt AcraStruct")
				return nil, err
			}
			rotated, err := acrawriter.CreateAcrastruct(decrypted, &keys.PublicKey{Value: newPublicKey}, binZoneID)
			if err != nil {
				logger.WithError(err).Errorln("Can't re-encrypt AcraStruct with rotated zone key")
				return nil, err
			}
			if stat, err := os.Stat(path); err != nil {
				logger.WithError(err).Errorln("Can't get stat info about file to retrieve current file permissions")
				return nil, err
			} else {
				if err := ioutil.WriteFile(path, rotated, stat.Mode()); err != nil {
					logger.WithError(err).Errorln("Can't write rotated AcraStruct with zone")
					return nil, err
				}
			}
		}
		output[zoneID] = result
		logger.Infoln("Finish rotate zone")
	}
	return output, nil
}

func main() {
	keysDir := flag.String("keys_dir", keystore.DefaultKeyDirShort, "Folder from which the keys will be loaded")
	fileMapConfig := flag.String("file_map_config", "", "Path to file with map of <ZoneId>: <FilePath>")
	//clientID := flag.String("client_id", "", "Client ID should be name of file with private key")

	logging.SetLogLevel(logging.LOG_VERBOSE)

	err := cmd.Parse(DEFAULT_CONFIG_PATH, SERVICE_NAME)
	if err != nil {
		log.WithError(err).Errorln("Can't parse args")
		os.Exit(1)
	}

	//cmd.ValidateClientID(*clientID)
	keystorage, err := initKeyStore(*keysDir)
	if err != nil {
		os.Exit(1)
	}
	fileMap, err := loadFileMap(*fileMapConfig)
	if err != nil {
		log.WithError(err).Errorln("Can't load config with map <ZoneId>: <FilePath>")
		os.Exit(1)
	}
	result, err := rotateFiles(fileMap, keystorage)
	if err != nil {
		log.WithError(err).Errorln("Can't rotate files")
		os.Exit(1)
	}
	jsonOutput, err := json.Marshal(result)
	if err != nil {
		log.WithError(err).Errorln("Can't encode result to json format")
		os.Exit(1)
	}
	fmt.Println(string(jsonOutput))
}
