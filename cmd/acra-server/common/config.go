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

package common

import (
	"errors"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/sqlparser/dialect"
	mysqlDialect "github.com/cossacklabs/acra/sqlparser/dialect/mysql"
	pgDialect "github.com/cossacklabs/acra/sqlparser/dialect/postgresql"
	"io/ioutil"

	acracensor "github.com/cossacklabs/acra/acra-censor"
	"github.com/cossacklabs/acra/encryptor"
	encryptorConfig "github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
)

// Config describes AcraServer configuration
type Config struct {
	dbPort                   int
	dbHost                   string
	detectPoisonRecords      bool
	stopOnPoison             bool
	scriptOnPoison           string
	withAPI                  bool
	acraConnectionString     string
	acraAPIConnectionString  string
	ConnectionWrapper        network.ConnectionWrapper
	HTTPAPIConnectionWrapper network.HTTPServerConnectionWrapper
	tlsClientIDExtractor     network.TLSClientIDExtractor
	mysql                    bool
	postgresql               bool
	debug                    bool
	censor                   acracensor.AcraCensorInterface
	TraceToLog               bool
	tableSchema              encryptorConfig.TableSchemaStore
	dataEncryptor            encryptor.DataEncryptor
	keystore                 keystore.ServerKeyStore
	traceOptions             []trace.StartOption
	serviceName              string
	configPath               string
}

// NewConfig returns new Config object
func NewConfig() (*Config, error) {
	schemaStore, err := encryptorConfig.NewMapTableSchemaStore()
	if err != nil {
		return nil, err
	}
	traceOptions := []trace.StartOption{trace.WithSpanKind(trace.SpanKindServer), trace.WithSampler(trace.AlwaysSample())}
	return &Config{mysql: false, postgresql: false, tableSchema: schemaStore, traceOptions: traceOptions}, nil
}

// ErrTwoDBSetup shows that AcraServer can connects only to one database at the same time
var ErrTwoDBSetup = errors.New("only one db supported at one time")

// SetDBConnectionSettings sets address of the database.
func (config *Config) SetDBConnectionSettings(host string, port int) {
	config.dbHost = host
	config.dbPort = port
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

// GetTableSchema returns table schema in use.
func (config *Config) GetTableSchema() encryptorConfig.TableSchemaStore {
	return config.tableSchema
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

// SetConfigPath sets AcraServer config path
func (config *Config) SetConfigPath(path string) {
	config.configPath = path
}

// GetConfigPath returns AcraServer config path
func (config *Config) GetConfigPath() string {
	return config.configPath
}

// GetAcraConnectionString returns AcraServer data connection string
func (config *Config) GetAcraConnectionString() string {
	return config.acraConnectionString
}

// GetAcraAPIConnectionString returns AcraServer API connection string
func (config *Config) GetAcraAPIConnectionString() string {
	return config.acraAPIConnectionString
}

// SetKeyStore sets keystore.
func (config *Config) SetKeyStore(k keystore.ServerKeyStore) {
	config.keystore = k
}

// GetKeyStore return configure KeyStore
func (config *Config) GetKeyStore() keystore.ServerKeyStore {
	return config.keystore
}

// GetTraceOptions return configured trace StartOptions
func (config *Config) GetTraceOptions() []trace.StartOption {
	return config.traceOptions
}

// SetServiceName sets AcraServer service name.
func (config *Config) SetServiceName(name string) {
	config.serviceName = name
}

// GetServiceName returns AcraServer service name.
func (config *Config) GetServiceName() string {
	return config.serviceName
}

// SetScriptOnPoison sets path to script to execute when poison record is triggered.
func (config *Config) SetScriptOnPoison(script string) {
	config.scriptOnPoison = script
}

// SetStopOnPoison tells AcraServer to shutdown when poison record is triggered.
func (config *Config) SetStopOnPoison(stop bool) {
	config.stopOnPoison = stop
}

// GetSQLDialect returns MySQL or PostgreSQL dialect depending on the configuration.
func (config *Config) GetSQLDialect() dialect.Dialect {
	if config.mysql {
		caseSensitiveTableName := config.GetTableSchema().GetDatabaseSettings().GetMySQLDatabaseSettings().GetCaseSensitiveTableIdentifiers()
		caseSensitiveTableNameOption := mysqlDialect.SetTableNameCaseSensitivity(caseSensitiveTableName)
		return mysqlDialect.NewMySQLDialect(caseSensitiveTableNameOption)
	}

	return pgDialect.NewPostgreSQLDialect()
}

// SetTLSClientIDExtractor set clientID extractor from TLS metadata
func (config *Config) SetTLSClientIDExtractor(tlsClientIDExtractor network.TLSClientIDExtractor) {
	config.tlsClientIDExtractor = tlsClientIDExtractor
}

// GetTLSClientIDExtractor return configured TLSClietIDExtractor
func (config *Config) GetTLSClientIDExtractor() network.TLSClientIDExtractor {
	return config.tlsClientIDExtractor
}
