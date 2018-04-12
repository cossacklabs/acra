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
	"crypto/tls"
	"encoding/json"
	"errors"

	"github.com/cossacklabs/acra/acracensor"
	"github.com/cossacklabs/acra/network"
	"io/ioutil"
)

const (
	HEX_BYTEA_FORMAT    int8 = 1
	ESCAPE_BYTEA_FORMAT int8 = 2
)

type Config struct {
	proxyCommandsPort       int
	byteaFormat             int8
	dbPort                  int
	proxyPort               int
	dbHost                  string
	proxyHost               string
	keysDir                 string
	scriptOnPoison          string
	stopOnPoison            bool
	withZone                bool
	withAPI                 bool
	wholeMatch              bool
	serverId                []byte
	acraConnectionString    string
	acraAPIConnectionString string
	tlsServerKeyPath        string
	tlsServerCertPath       string
	ConnectionWrapper       network.ConnectionWrapper
	mysql                   bool
	postgresql              bool
	configPath              string
	debug                   bool
	censor                  acracensor.AcracensorInterface
	tlsConfig               *tls.Config
}

type UIEditableConfig struct {
	DbHost            string `json:"db_host"`
	DbPort            int    `json:"db_port"`
	ProxyCommandsPort int    `json:"commands_port"`
	Debug             bool   `json:"debug"`
	ScriptOnPoison    string `json:"poisonscript"`
	StopOnPoison      bool   `json:"poisonshutdown"`
	WithZone          bool   `json:"zonemode"`
}

func NewConfig() *Config {
	return &Config{withZone: false, stopOnPoison: false, wholeMatch: true, mysql: false, postgresql: false}
}

var ErrTwoDBSetup = errors.New("only one db supported at one time")

func (config *Config) SetCensor(censorConfigPath string) error {
	acraCensor := &acracensor.AcraCensor{}
	config.censor = acraCensor
	//skip if flag not specified
	if censorConfigPath == "" {
		return nil
	}
	configuration, err := ioutil.ReadFile(censorConfigPath)
	if err != nil {
		return err
	}
	err = acraCensor.LoadConfiguration(configuration)
	if err != nil {
		return err
	}
	config.censor = acraCensor
	return nil
}
func (config *Config) GetCensor() acracensor.AcracensorInterface {
	return config.censor
}

func (config *Config) SetMySQL(useMySQL bool) error {
	if config.postgresql && useMySQL {
		return ErrTwoDBSetup
	}
	config.mysql = useMySQL
	return nil
}
func (config *Config) UseMySQL() bool {
	return config.mysql
}

func (config *Config) UsePostgreSQL() bool {
	// default true if two settings is false
	if !(config.mysql || config.postgresql) {
		return true
	}
	return config.postgresql
}

func (config *Config) SetPostgresql(usePostgresql bool) error {
	if config.mysql && usePostgresql {
		return ErrTwoDBSetup
	}
	config.postgresql = usePostgresql
	return nil
}
func (config *Config) GetTLSServerKeyPath() string {
	return config.tlsServerKeyPath
}
func (config *Config) GetTLSServerCertPath() string {
	return config.tlsServerCertPath
}
func (config *Config) SetTLSServerKeyPath(path string) {
	config.tlsServerKeyPath = path
}
func (config *Config) SetTLSServerCertPath(path string) {
	config.tlsServerCertPath = path
}
func (config *Config) SetAcraConnectionString(str string) {
	config.acraConnectionString = str
}
func (config *Config) SetAcraAPIConnectionString(str string) {
	config.acraAPIConnectionString = str
}
func (config *Config) SetScriptOnPoison(scriptPath string) {
	config.scriptOnPoison = scriptPath
}
func (config *Config) GetScriptOnPoison() string {
	return config.scriptOnPoison
}
func (config *Config) SetStopOnPoison(stop bool) {
	config.stopOnPoison = stop
}
func (config *Config) GetStopOnPoison() bool {
	return config.stopOnPoison
}
func (config *Config) SetDebug(value bool) {
	config.debug = value
}
func (config *Config) GetDebug() bool {
	return config.debug
}
func (config *Config) GetWithZone() bool {
	return config.withZone
}
func (config *Config) SetWithZone(wz bool) {
	config.withZone = wz
}
func (config *Config) SetEnableHTTPApi(api bool) {
	config.withAPI = api
}
func (config *Config) GetEnableHTTPApi() bool {
	return config.withAPI
}
func (config *Config) GetProxyHost() string {
	return config.proxyHost
}
func (config *Config) SetProxyHost(host string) error {
	config.proxyHost = host
	return nil
}
func (config *Config) GetProxyPort() int {
	return config.proxyPort
}
func (config *Config) GetProxyCommandsPort() int {
	return config.proxyCommandsPort
}
func (config *Config) SetProxyPort(port int) error {
	config.proxyPort = port
	return nil
}
func (config *Config) SetProxyCommandsPort(port int) error {
	config.proxyCommandsPort = port
	return nil
}
func (config *Config) GetDBHost() string {
	return config.dbHost
}
func (config *Config) SetDBHost(host string) error {
	config.dbHost = host
	return nil
}
func (config *Config) GetDBPort() int {
	return config.dbPort
}
func (config *Config) SetDBPort(port int) error {
	config.dbPort = port
	return nil
}
func (config *Config) SetByteaFormat(format int8) error {
	if format != HEX_BYTEA_FORMAT && format != ESCAPE_BYTEA_FORMAT {
		return errors.New("Incorrect bytea format")
	}
	config.byteaFormat = format
	return nil
}
func (config *Config) GetByteaFormat() int8 {
	return config.byteaFormat
}
func (config *Config) GetKeysDir() string {
	return config.keysDir
}
func (config *Config) SetKeysDir(keysDir string) error {
	config.keysDir = keysDir
	return nil
}
func (config *Config) GetServerId() []byte {
	return config.serverId
}
func (config *Config) SetServerId(serverId []byte) error {
	config.serverId = serverId
	return nil
}
func (config *Config) GetWholeMatch() bool {
	return config.wholeMatch
}
func (config *Config) SetWholeMatch(value bool) {
	config.wholeMatch = value
}
func (config *Config) GetConfigPath() string {
	return config.configPath
}
func (config *Config) SetConfigPath(value string) {
	config.configPath = value
}

func (config *Config) ToJson() ([]byte, error) {
	var s UIEditableConfig
	s.DbHost = config.GetDBHost()
	s.DbPort = config.GetDBPort()
	s.ProxyCommandsPort = config.GetProxyCommandsPort()
	s.Debug = config.GetDebug()
	s.ScriptOnPoison = config.GetScriptOnPoison()
	s.StopOnPoison = config.GetStopOnPoison()
	s.WithZone = config.GetWithZone()
	out, err := json.Marshal(s)
	return out, err
}

func (config *Config) GetAcraConnectionString() string {
	return config.acraConnectionString
}

func (config *Config) GetAcraAPIConnectionString() string {
	return config.acraAPIConnectionString
}

func (config *Config) SetTLSConfig(tlsConfig *tls.Config) {
	config.tlsConfig = tlsConfig
}
func (config *Config) GetTLSConfig() *tls.Config {
	return config.tlsConfig
}
