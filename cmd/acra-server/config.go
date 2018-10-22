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

package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"

	"github.com/cossacklabs/acra/acra-censor"
	"github.com/cossacklabs/acra/network"
	"io/ioutil"
)

// Possible bytea formats
const (
	HEX_BYTEA_FORMAT    int8 = 1
	ESCAPE_BYTEA_FORMAT int8 = 2
)

// Config describes AcraServer configuration
type Config struct {
	connectorAPIPort        int
	byteaFormat             int8
	dbPort                  int
	connectorPort           int
	dbHost                  string
	connectorHost           string
	keysDir                 string
	detectPoisonRecords     bool
	scriptOnPoison          string
	stopOnPoison            bool
	withZone                bool
	withAPI                 bool
	wholeMatch              bool
	serverID                []byte
	acraConnectionString    string
	acraAPIConnectionString string
	tlsServerKeyPath        string
	tlsServerCertPath       string
	ConnectionWrapper       network.ConnectionWrapper
	mysql                   bool
	postgresql              bool
	configPath              string
	debug                   bool
	censor                  acracensor.AcraCensorInterface
	tlsConfig               *tls.Config
	tracing                 bool
	withConnector           bool
	TraceToLog              bool
}

// UIEditableConfig describes which parts of AcraServer configuration can be changed from AcraWebconfig page
type UIEditableConfig struct {
	DbHost           string `json:"db_host"`
	DbPort           int    `json:"db_port"`
	ConnectorAPIPort int    `json:"incoming_connection_api_port"`
	Debug            bool   `json:"debug"`
	ScriptOnPoison   string `json:"poison_run_script_file"`
	StopOnPoison     bool   `json:"poison_shutdown_enable"`
	WithZone         bool   `json:"zonemode_enable"`
}

// NewConfig returns new Config object
func NewConfig() *Config {
	return &Config{withZone: false, stopOnPoison: false, wholeMatch: true, mysql: false, postgresql: false, withConnector: true}
}

// ErrTwoDBSetup shows that AcraServer can connects only to one database at the same time
var ErrTwoDBSetup = errors.New("only one db supported at one time")

// WithConnector shows that AcraServer expects connections from AcraConnector
func (config *Config) WithConnector() bool {
	return config.withConnector
}

// SetWithConnector set that acra-server will or not accept connections from acra-connector
func (config *Config) SetWithConnector(v bool) {
	config.withConnector = v
}

// GetTracing status on/off
func (config *Config) GetTracing() bool {
	return config.tracing
}

// SetTracing status on/off
func (config *Config) SetTracing(v bool) {
	config.tracing = v
}

// SetCensor creates AcraCensor and sets its configuration
func (config *Config) SetCensor(censorConfigPath string) error {
	censor := acracensor.NewAcraCensor()
	config.censor = censor
	//skip if flag not specified
	if censorConfigPath == "" {
		return nil
	}
	configuration, err := ioutil.ReadFile(censorConfigPath)
	if err != nil {
		return err
	}
	err = censor.LoadConfiguration(configuration)
	if err != nil {
		return err
	}
	return nil
}

// GetCensor returns AcraCensor associated with AcraServer
func (config *Config) GetCensor() acracensor.AcraCensorInterface {
	return config.censor
}

// SetMySQL sets that AcraServer should connect to MySQL database
func (config *Config) SetMySQL(useMySQL bool) error {
	if config.postgresql && useMySQL {
		return ErrTwoDBSetup
	}
	config.mysql = useMySQL
	return nil
}

// UseMySQL returns if AcraServer should connect to MySQL database
func (config *Config) UseMySQL() bool {
	return config.mysql
}

// UsePostgreSQL returns if AcraServer should connect to PostgreSQL database
func (config *Config) UsePostgreSQL() bool {
	// default true if two settings is false
	if !(config.mysql || config.postgresql) {
		return true
	}
	return config.postgresql
}

// SetPostgresql sets that AcraServer should connect to PostgreSQL database
func (config *Config) SetPostgresql(usePostgresql bool) error {
	if config.mysql && usePostgresql {
		return ErrTwoDBSetup
	}
	config.postgresql = usePostgresql
	return nil
}

// GetTLSServerKeyPath returns path to TLS server certificate's key
func (config *Config) GetTLSServerKeyPath() string {
	return config.tlsServerKeyPath
}

// GetTLSServerCertPath returns path to server TLS Certificate
func (config *Config) GetTLSServerCertPath() string {
	return config.tlsServerCertPath
}

// SetTLSServerKeyPath sets path to TLS server certificate's key
func (config *Config) SetTLSServerKeyPath(path string) {
	config.tlsServerKeyPath = path
}

// SetTLSServerCertPath sets path to server TLS Certificate
func (config *Config) SetTLSServerCertPath(path string) {
	config.tlsServerCertPath = path
}

// SetAcraConnectionString sets AcraServer data connection string
func (config *Config) SetAcraConnectionString(str string) {
	config.acraConnectionString = str
}

// SetAcraAPIConnectionString sets AcraServer API connection string
func (config *Config) SetAcraAPIConnectionString(str string) {
	config.acraAPIConnectionString = str
}

// SetDetectPoisonRecords sets if AcraServer should detect Poison records
func (config *Config) SetDetectPoisonRecords(val bool) {
	config.detectPoisonRecords = val
}

// DetectPoisonRecords returns if AcraServer should detect Poison records
func (config *Config) DetectPoisonRecords() bool {
	return config.detectPoisonRecords
}

// SetScriptOnPoison sets path to script to execute if AcraServer detected Poison records
func (config *Config) SetScriptOnPoison(scriptPath string) {
	config.scriptOnPoison = scriptPath
}

// GetScriptOnPoison gets path to script to execute if AcraServer detected Poison records
func (config *Config) GetScriptOnPoison() string {
	return config.scriptOnPoison
}

// SetStopOnPoison sets if AcraServer should shutdown if detected Poison records
func (config *Config) SetStopOnPoison(stop bool) {
	config.stopOnPoison = stop
}

// GetStopOnPoison returns if AcraServer should shutdown if detected Poison records
func (config *Config) GetStopOnPoison() bool {
	return config.stopOnPoison
}

// SetDebug sets if AcraServer should run in debug mode and print debug logs
func (config *Config) SetDebug(value bool) {
	config.debug = value
}

// GetDebug returns if AcraServer should run in debug mode and print debug logs
func (config *Config) GetDebug() bool {
	return config.debug
}

// GetWithZone returns if AcraServer should try to decrypt AcraStructs using zones
func (config *Config) GetWithZone() bool {
	return config.withZone
}

// SetWithZone sets if AcraServer should try to decrypt AcraStructs using zones
func (config *Config) SetWithZone(wz bool) {
	config.withZone = wz
}

// SetEnableHTTPAPI sets if AcraServer should listen to HTTP commands
func (config *Config) SetEnableHTTPAPI(api bool) {
	config.withAPI = api
}

// GetEnableHTTPAPI returns if AcraServer should listen to HTTP commands
func (config *Config) GetEnableHTTPAPI() bool {
	return config.withAPI
}

// GetConnectorHost returns AcraServer connection host
func (config *Config) GetConnectorHost() string {
	return config.connectorHost
}

// SetConnectorHost sets AcraServer connection host
func (config *Config) SetConnectorHost(host string) error {
	config.connectorHost = host
	return nil
}

// GetConnectorPort returns AcraServer connection port
func (config *Config) GetConnectorPort() int {
	return config.connectorPort
}

// GetConnectorAPIPort returns AcraServer connection API port
func (config *Config) GetConnectorAPIPort() int {
	return config.connectorAPIPort
}

// SetConnectorPort sets AcraServer connection port
func (config *Config) SetConnectorPort(port int) error {
	config.connectorPort = port
	return nil
}

// SetConnectorAPIPort sets AcraServer connection API port
func (config *Config) SetConnectorAPIPort(port int) error {
	config.connectorAPIPort = port
	return nil
}

// GetDBHost returns AcraServer database host
func (config *Config) GetDBHost() string {
	return config.dbHost
}

// SetDBHost sets AcraServer database host
func (config *Config) SetDBHost(host string) error {
	config.dbHost = host
	return nil
}

// GetDBPort returns AcraServer database port
func (config *Config) GetDBPort() int {
	return config.dbPort
}

// SetDBPort sets AcraServer database host
func (config *Config) SetDBPort(port int) error {
	config.dbPort = port
	return nil
}

// SetByteaFormat sets bytea format for connecting to database
func (config *Config) SetByteaFormat(format int8) error {
	if format != HEX_BYTEA_FORMAT && format != ESCAPE_BYTEA_FORMAT {
		return errors.New("incorrect bytea format")
	}
	config.byteaFormat = format
	return nil
}

// GetByteaFormat returns bytea format for connecting to database
func (config *Config) GetByteaFormat() int8 {
	return config.byteaFormat
}

// GetKeysDir returns key directory name
func (config *Config) GetKeysDir() string {
	return config.keysDir
}

// SetKeysDir sets key directory name
func (config *Config) SetKeysDir(keysDir string) error {
	config.keysDir = keysDir
	return nil
}

// GetServerID returns AcraServer SecureSession ID
func (config *Config) GetServerID() []byte {
	return config.serverID
}

// SetServerID sets AcraServer SecureSession ID
func (config *Config) SetServerID(serverID []byte) error {
	config.serverID = serverID
	return nil
}

// GetWholeMatch returns if AcraServer assumes that whole database cell has one AcraStruct
func (config *Config) GetWholeMatch() bool {
	return config.wholeMatch
}

// SetWholeMatch sets that AcraServer assumes that whole database cell has one AcraStruct
func (config *Config) SetWholeMatch(value bool) {
	config.wholeMatch = value
}

// GetConfigPath returns AcraServer config path
func (config *Config) GetConfigPath() string {
	return config.configPath
}

// SetConfigPath sets AcraServer config path
func (config *Config) SetConfigPath(value string) {
	config.configPath = value
}

// ToJSON AcraServer editable config in JSON format
func (config *Config) ToJSON() ([]byte, error) {
	var s UIEditableConfig
	s.DbHost = config.GetDBHost()
	s.DbPort = config.GetDBPort()
	s.ConnectorAPIPort = config.GetConnectorAPIPort()
	s.Debug = config.GetDebug()
	s.ScriptOnPoison = config.GetScriptOnPoison()
	s.StopOnPoison = config.GetStopOnPoison()
	s.WithZone = config.GetWithZone()
	out, err := json.Marshal(s)
	return out, err
}

// GetAcraConnectionString returns AcraServer data connection string
func (config *Config) GetAcraConnectionString() string {
	return config.acraConnectionString
}

// GetAcraAPIConnectionString returns AcraServer API connection string
func (config *Config) GetAcraAPIConnectionString() string {
	return config.acraAPIConnectionString
}

// SetTLSConfig sets TLS config
func (config *Config) SetTLSConfig(tlsConfig *tls.Config) {
	config.tlsConfig = tlsConfig
}

// GetTLSConfig returns TLS config
func (config *Config) GetTLSConfig() *tls.Config {
	return config.tlsConfig
}
