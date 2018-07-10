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

type AcraReaderConfig struct {
	keysDir                      string
	scriptOnPoison               string
	stopOnPoison                 bool
	serverId                     []byte
	incomingConnectionHTTPString string
	incomingConnectionGRPCString string
	ConnectionWrapper            network.ConnectionWrapper
	configPath                   string
	debug                        bool
}

func NewConfig() *AcraReaderConfig {
	return &AcraReaderConfig{stopOnPoison: false}
}

func (a *AcraReaderConfig) KeysDir() string {
	return a.keysDir
}

func (a *AcraReaderConfig) SetKeysDir(keysDir string) {
	a.keysDir = keysDir
}

func (a *AcraReaderConfig) ScriptOnPoison() string {
	return a.scriptOnPoison
}

func (a *AcraReaderConfig) SetScriptOnPoison(scriptOnPoison string) {
	a.scriptOnPoison = scriptOnPoison
}

func (a *AcraReaderConfig) StopOnPoison() bool {
	return a.stopOnPoison
}

func (a *AcraReaderConfig) SetStopOnPoison(stopOnPoison bool) {
	a.stopOnPoison = stopOnPoison
}

func (a *AcraReaderConfig) ServerId() []byte {
	return a.serverId
}

func (a *AcraReaderConfig) SetServerId(serverId []byte) {
	a.serverId = serverId
}

func (a *AcraReaderConfig) IncomingConnectionHTTPString() string {
	return a.incomingConnectionHTTPString
}

func (a *AcraReaderConfig) SetIncomingConnectionHTTPString(incomingConnectionHTTPString string) {
	a.incomingConnectionHTTPString = incomingConnectionHTTPString
}

func (a *AcraReaderConfig) IncomingConnectionGRPCString() string {
	return a.incomingConnectionGRPCString
}

func (a *AcraReaderConfig) SetIncomingConnectionGRPCString(incomingConnectionGRPCString string) {
	a.incomingConnectionGRPCString = incomingConnectionGRPCString
}

func (a *AcraReaderConfig) ConfigPath() string {
	return a.configPath
}

func (a *AcraReaderConfig) SetConfigPath(configPath string) {
	a.configPath = configPath
}

func (a *AcraReaderConfig) Debug() bool {
	return a.debug
}

func (a *AcraReaderConfig) SetDebug(debug bool) {
	a.debug = debug
}
