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

// Package main is entry point for AcraServer utility. AcraServer is the server responsible for decrypting all
// the database responses and forwarding them back to clients. AcraServer waits to connection from AcraConnector.
// When the first AcraConnector connection arrives, AcraServer initialises secure communication via TLS or
// Themis Secure Session. After a successful initialisation of the session, AcraServer creates a database connection
// and starts forwarding all the requests coming from AcraConnector into the database.
// Every incoming request to AcraServer is passed through AcraCensor (Acra's firewall). AcraCensor will pass allowed
// queries and return error on forbidden ones.
// Upon receiving the answer, AcraServer attempts to unpack the AcraStruct and to decrypt the payload. After that,
// AcraServer will replace the AcraStruct with the decrypted payload, change the packet's length, and return
// the answer to the application via AcraConnector.
// If AcraServer detects a poison record within the AcraStruct's decryption stream, AcraServer will either
// shut down the decryption, run an alarm script, or do both, depending on the pre-set parameters.
//
// https://github.com/cossacklabs/acra/wiki/How-AcraServer-works
package main

import (
	"fmt"
	"github.com/cossacklabs/acra/utils"
	"io/ioutil"
)

// ErrGetAuthDataFromFile can't find auth config error
var ErrGetAuthDataFromFile = fmt.Errorf("no auth config [%v]", authPath)

func getAuthDataFromFile(authPath string) (data []byte, err error) {
	configPath, err := utils.AbsPath(authPath)
	if err != nil {
		return nil, err
	}
	exists, err := utils.FileExists(configPath)
	if err != nil {
		return nil, err
	}
	if exists {
		fileContent, err := ioutil.ReadFile(configPath)
		if err != nil {
			return nil, err
		}
		data = fileContent
		return data, nil
	}
	return nil, ErrGetAuthDataFromFile
}
