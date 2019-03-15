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
	"encoding/json"
	"errors"
	"github.com/cossacklabs/acra/acra-censor"
	"github.com/cossacklabs/acra/encryptor"
	encryptorConfig "github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
	"io/ioutil"
)

// Config describes AcraServer configuration
type Config struct {
	dbPort                  int
	dbHost                  string
	detectPoisonRecords     bool
	stopOnPoison            bool
	scriptOnPoison          string
	withZone                bool
	withAPI                 bool
	wholeMatch              bool
	acraConnectionString    string
	acraAPIConnectionString string
	ConnectionWrapper       network.ConnectionWrapper
	mysql                   bool
	postgresql              bool
	debug                   bool
	censor                  acracensor.AcraCensorInterface
	withConnector           bool
	TraceToLog              bool
	tableSchema             *encryptorConfig.MapTableSchemaStore
	dataEncryptor           encryptor.DataEncryptor
	keystore                keystore.KeyStore
	traceOptions            []trace.StartOption
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
func NewConfig() (*Config, error) {
	schemaStore, err := encryptorConfig.NewMapTableSchemaStore()
	if err != nil {
		return nil, err
	}
	traceOptions := []trace.StartOption{trace.WithSpanKind(trace.SpanKindServer), trace.WithSampler(trace.AlwaysSample())}
	return &Config{withZone: false, wholeMatch: true, mysql: false, postgresql: false, withConnector: true, tableSchema: schemaStore, traceOptions: traceOptions}, nil
}

// ErrTwoDBSetup shows that AcraServer can connects only to one database at the same time
var ErrTwoDBSetup = errors.New("only one db supported at one time")

func (config *Config) setDBConnectionSettings(host string, port int) {
	config.dbHost = host
	config.dbPort = port
}

// WithConnector shows that AcraServer expects connections from AcraConnector
func (config *Config) WithConnector() bool {
	return config.withConnector
}

// setWithConnector set that acra-server will or not accept connections from acra-connector
func (config *Config) setWithConnector(v bool) {
	config.withConnector = v
}

// LoadMapTableSchemaConfig load table schemas from config file
func (config *Config) LoadMapTableSchemaConfig(path string) error {
	mapConfig, err := ioutil.ReadFile(path)
	if err != nil {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).WithError(err).Errorln("Can't read config for encryptor")
		return err
	}
	schema, err := encryptorConfig.MapTableSchemaStoreFromConfig(mapConfig)
	if err != nil {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).WithError(err).Errorln("Can't parse table schemas from config")
		return err
	}
	config.tableSchema = schema
	return nil
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

// UseMySQL returns if AcraServer should connect to MySQL database
func (config *Config) UseMySQL() bool {
	return config.mysql
}

// UsePostgreSQL returns if AcraServer should connect to PostgreSQL database
func (config *Config) UsePostgreSQL() bool {
	return config.postgresql
}

// SetDatabaseType set mysql or postgresql, return ErrTwoDBSetup if both true, set postgresql true if both false
func (config *Config) SetDatabaseType(mysql, postgresql bool) error {
	if mysql && postgresql {
		return ErrTwoDBSetup
	}
	if !(mysql || postgresql) {
		postgresql = true
	}
	config.postgresql = postgresql
	config.mysql = mysql
	return nil
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

// GetDBHost returns AcraServer database host
func (config *Config) GetDBHost() string {
	return config.dbHost
}

// GetDBPort returns AcraServer database port
func (config *Config) GetDBPort() int {
	return config.dbPort
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
	return defaultConfigPath
}

// ToJSON AcraServer editable config in JSON format
func (config *Config) ToJSON() ([]byte, error) {
	var s UIEditableConfig
	var err error
	s.DbHost, s.DbPort, err = network.SplitConnectionString(config.acraConnectionString)
	if err != nil {
		return nil, err
	}
	s.DbHost, s.ConnectorAPIPort, err = network.SplitConnectionString(config.acraAPIConnectionString)
	if err != nil {
		return nil, err
	}
	s.Debug = config.GetDebug()
	s.ScriptOnPoison = config.scriptOnPoison
	s.StopOnPoison = config.stopOnPoison
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

// setKeyStore set keystore
func (config *Config) setKeyStore(k keystore.KeyStore) {
	config.keystore = k
}

// GetKeyStore return configure KeyStore
func (config *Config) GetKeyStore() keystore.KeyStore {
	return config.keystore
}

// GetTraceOptions return configured trace StartOptions
func (config *Config) GetTraceOptions() []trace.StartOption {
	return config.traceOptions
}
