// Copyright 2018, Cossack Labs Limited
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
	"github.com/cossacklabs/acra/network"
)

type AcraTranslatorConfig struct {
	keysDir                      string
	detectPoisonRecords          bool
	scriptOnPoison               string
	stopOnPoison                 bool
	serverId                     []byte
	incomingConnectionHTTPString string
	incomingConnectionGRPCString string
	ConnectionWrapper            network.ConnectionWrapper
	configPath                   string
	debug                        bool
}

func NewConfig() *AcraTranslatorConfig {
	return &AcraTranslatorConfig{stopOnPoison: false}
}

func (a *AcraTranslatorConfig) KeysDir() string {
	return a.keysDir
}

func (a *AcraTranslatorConfig) SetKeysDir(keysDir string) {
	a.keysDir = keysDir
}

func (a *AcraTranslatorConfig) SetDetectPoisonRecords(val bool) {
	a.detectPoisonRecords = val
}
func (a *AcraTranslatorConfig) DetectPoisonRecords() bool {
	return a.detectPoisonRecords
}

func (a *AcraTranslatorConfig) ScriptOnPoison() string {
	return a.scriptOnPoison
}

func (a *AcraTranslatorConfig) SetScriptOnPoison(scriptOnPoison string) {
	a.scriptOnPoison = scriptOnPoison
}

func (a *AcraTranslatorConfig) StopOnPoison() bool {
	return a.stopOnPoison
}

func (a *AcraTranslatorConfig) SetStopOnPoison(stopOnPoison bool) {
	a.stopOnPoison = stopOnPoison
}

func (a *AcraTranslatorConfig) ServerId() []byte {
	return a.serverId
}

func (a *AcraTranslatorConfig) SetServerId(serverId []byte) {
	a.serverId = serverId
}

func (a *AcraTranslatorConfig) IncomingConnectionHTTPString() string {
	return a.incomingConnectionHTTPString
}

func (a *AcraTranslatorConfig) SetIncomingConnectionHTTPString(incomingConnectionHTTPString string) {
	a.incomingConnectionHTTPString = incomingConnectionHTTPString
}

func (a *AcraTranslatorConfig) IncomingConnectionGRPCString() string {
	return a.incomingConnectionGRPCString
}

func (a *AcraTranslatorConfig) SetIncomingConnectionGRPCString(incomingConnectionGRPCString string) {
	a.incomingConnectionGRPCString = incomingConnectionGRPCString
}

func (a *AcraTranslatorConfig) ConfigPath() string {
	return a.configPath
}

func (a *AcraTranslatorConfig) SetConfigPath(configPath string) {
	a.configPath = configPath
}

func (a *AcraTranslatorConfig) Debug() bool {
	return a.debug
}

func (a *AcraTranslatorConfig) SetDebug(debug bool) {
	a.debug = debug
}
