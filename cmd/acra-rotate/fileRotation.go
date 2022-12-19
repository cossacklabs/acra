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
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"
)

// loadFileMap read file with <path>, parse json and return it as KeyIDFileMap
func loadFileMap(path string) (KeyIDFileMap, error) {
	configData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(configData)
}

// RotateData store new public key and paths of files that was rotated
type RotateData struct {
	NewPublicKey []byte   `json:"new_public_key"`
	FilePaths    []string `json:"file_paths"`
}

// RotateResult store result of rotation
type RotateResult map[string]*RotateData

// rotateFiles generate new key pair for each clientID in KeyIDFileMap and re-encrypt all files encrypted with each id
func rotateFiles(fileMap KeyIDFileMap, keyStore RotateStorageKeyStore, dryRun bool) (RotateResult, error) {
	rotator, err := newRotator(keyStore)
	if err != nil {
		return nil, err
	}
	defer rotator.clearKeys()
	output := RotateResult{}
	for clientID, paths := range fileMap {
		logger := log.WithField("Key ID", clientID)
		binID := []byte(clientID)
		newPublicKey, err := rotator.getRotatedPublicKey(binID)
		if err != nil {
			logger.WithError(err).Errorln("Can't rotate key")
			return nil, err
		}
		result := &RotateData{NewPublicKey: newPublicKey.Value}
		for _, path := range paths {
			fileLogger := logger.WithField("filepath", path)
			result.FilePaths = append(result.FilePaths, path)
			acraStruct, err := ioutil.ReadFile(path)
			if err != nil {
				fileLogger.WithError(err).Errorf("Can't read file %s", path)
				return nil, err
			}

			rotated, err := rotator.rotateAcrastruct(binID, acraStruct)
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
					fileLogger.WithError(err).Errorln("Can't write rotated AcraStruct")
					return nil, err
				}
			}
			fileLogger.Infof("Finish rotate file")
		}
		output[clientID] = result
		logger.Infoln("Finish rotate")
	}
	if !dryRun {
		if err := rotator.saveRotatedKeys(); err != nil {
			log.WithError(err).Errorln("Can't save rotated keys")
		}
	}
	return output, nil
}

// runFileRotation read map clientIDs to files, re-generate key pairs and re-encrypt files
func runFileRotation(fileMapConfigPath string, keystorage RotateStorageKeyStore, dryRun bool) {
	fileMap, err := loadFileMap(fileMapConfigPath)
	if err != nil {
		log.WithError(err).Errorln("Can't load config with map <ClientId>: <FilePath>")
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
