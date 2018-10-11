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

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/cossacklabs/acra/keystore"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
)

// loadFileMap read file with <path>, parse json and return it as ZoneIDFileMap
func loadFileMap(path string) (ZoneIDFileMap, error) {
	configData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(configData)
}

// ZoneRotateData store new public key and paths of files that was rotated
type ZoneRotateData struct {
	NewPublicKey []byte   `json:"new_public_key"`
	FilePaths    []string `json:"file_paths"`
}

// ZoneRotateResult store result of rotation
type ZoneRotateResult map[string]*ZoneRotateData

// rotateFiles generate new key pair for each zone in ZoneIDFileMap and re-encrypt all files encrypted with each zone
func rotateFiles(fileMap ZoneIDFileMap, keyStore keystore.KeyStore, dryRun bool) (ZoneRotateResult, error) {
	rotator, err := newRotator(keyStore)
	if err != nil {
		return nil, err
	}
	defer rotator.clearKeys()
	output := ZoneRotateResult{}
	for zoneID, paths := range fileMap {
		logger := log.WithField("zone_id", zoneID)
		binZoneID := []byte(zoneID)
		newPublicKey, err := rotator.getRotatedPublicKey(binZoneID)
		if err != nil {
			logger.WithError(err).Errorln("Can't rotate zone key")
			return nil, err
		}
		result := &ZoneRotateData{NewPublicKey: newPublicKey.Value}
		for _, path := range paths {
			fileLogger := logger.WithField("filepath", path)
			result.FilePaths = append(result.FilePaths, path)
			acraStruct, err := ioutil.ReadFile(path)
			if err != nil {
				fileLogger.WithError(err).Errorf("Can't read file %s", path)
				return nil, err
			}

			rotated, err := rotator.rotateAcrastruct(binZoneID, acraStruct)
			if err != nil {
				fileLogger.WithField("acrastruct", hex.EncodeToString(acraStruct)).WithError(err).Errorln("Can't rotate data")
				return nil, err
			}
			stat, err := os.Stat(path)
			if err != nil {
				fileLogger.WithError(err).Errorln("Can't get stat info about file to retrieve current file permissions")
				return nil, err
			}
			if !dryRun {
				if err := ioutil.WriteFile(path, rotated, stat.Mode()); err != nil {
					fileLogger.WithError(err).Errorln("Can't write rotated AcraStruct with zone")
					return nil, err
				}
			}
			fileLogger.Infof("Finish rotate file")
		}
		output[zoneID] = result
		logger.Infoln("Finish rotate zone")
	}
	if !dryRun {
		if err := rotator.saveRotatedKeys(); err != nil {
			log.WithError(err).Errorln("Can't save rotated keys")
		}
	}
	return output, nil
}

// runFileRotation read map zones to files, re-generate zone key pairs and re-encrypt files
func runFileRotation(fileMapConfigPath string, keystorage keystore.KeyStore, dryRun bool) {
	fileMap, err := loadFileMap(fileMapConfigPath)
	if err != nil {
		log.WithError(err).Errorln("Can't load config with map <ZoneId>: <FilePath>")
		os.Exit(1)
	}
	result, err := rotateFiles(fileMap, keystorage, dryRun)
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
