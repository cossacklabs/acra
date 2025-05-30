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
// the database responses and forwarding them back to clients. AcraServer waits to connection from application.
// When the first connection arrives, AcraServer initialises secure communication via TLS.
// After a successful initialisation of the session, AcraServer creates a database connection
// and starts forwarding all the requests coming from application into the database.
// Every incoming request to AcraServer is passed through AcraCensor (Acra's firewall). AcraCensor will pass allowed
// queries and return error on forbidden ones.
// Upon receiving the answer, AcraServer attempts to unpack the AcraStruct and to decrypt the payload. After that,
// AcraServer will replace the AcraStruct with the decrypted payload, change the packet's length, and return
// the answer to the application.
// If AcraServer detects a poison record within the AcraStruct's decryption stream, AcraServer will either
// shut down the decryption, run an alarm script, or do both, depending on the pre-set parameters.
//
// https://github.com/cossacklabs/acra/wiki/How-AcraServer-works
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/cmd/acra-server/common"
	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/mysql"
	"github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/encryptor/base/config_loader"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	filesystemBackendV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/acra/pseudonymization"
	pseudonymizationCommon "github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/cossacklabs/acra/pseudonymization/storage"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/utils/args"
)

var restartSignalsChannel chan os.Signal
var errorSignalChannel chan os.Signal

// Constants used by AcraServer.
const (
	DefaultAcraServerWaitTimeout = 10
	GracefulRestartEnv           = "GRACEFUL_RESTART"
	ServiceName                  = "acra-server"
	SignalToStartForkedProcess   = "forked process is allowed to continue"

	// We use this values as a file descriptors pointers on SIGHUP signal processing.
	// We definitely know (because we implement this), that new forked process starts
	// with three descriptors in mind - stdin (0), stdout (1), stderr(2). And then we
	// use MAIN (Acra) (3), API (4) and PIPE (5) descriptors. Take a look at callback
	// function that is called on SIGHUP event for more details
	DescriptorAcra = 3
	DescriptorAPI  = 4
	DescriptorPipe = 5
)

// DefaultConfigPath relative path to config which will be parsed as default
var DefaultConfigPath = utils.GetConfigPathByName(ServiceName)

const tlsAuthNotSet = -1

// ErrShutdownTimeout occurs if we can't perform correct exit from realMain function (when we can't stop background goroutines used to handle system signals)
var ErrShutdownTimeout = errors.New("can't correctly stop all background goroutines on main function level")

// ErrPipeWrite occurs if we can't write to inter-process pipe (that we use for forked and parent processes synchronization upon SIGHUP handling)
var ErrPipeWrite = errors.New("can't write exit signal to pipe")

// ErrPipeReadWrongSignal occurs if we read unexpected signal from pipe between parent and forked processes
var ErrPipeReadWrongSignal = errors.New("wrong signal has been read from pipe")

func main() {
	err := realMain()
	if err != nil {
		os.Exit(1)
	}
}

func registerFlags(flagSet *flag.FlagSet) {
	flagSet.String("logging_format", "plaintext", "Logging format: plaintext, json or CEF")
	flagSet.String("db_host", "", "Host to db")
	flagSet.Int("db_port", 5432, "Port to db")
	flagSet.String("incoming_connection_prometheus_metrics_string", "", "URL (tcp://host:port) which will be used to expose Prometheus metrics (<URL>/metrics address to pull metrics)")
	flagSet.String("incoming_connection_host", cmd.DefaultAcraServerHost, "Host for AcraServer")
	flagSet.Int("incoming_connection_port", cmd.DefaultAcraServerPort, "Port for AcraServer")
	flagSet.Int("incoming_connection_api_port", cmd.DefaultAcraServerAPIPort, "Port for AcraServer for HTTP API")
	flagSet.String("keys_dir", keystore.DefaultKeyDirShort, "Folder from which will be loaded keys")
	flagSet.Bool("keystore_cache_on_start_enable", true, "Load all keys to cache on start")
	flagSet.Int("keystore_cache_size", keystore.DefaultCacheSize, fmt.Sprintf("Maximum number of keys stored in in-memory LRU cache in encrypted form. 0 - no limits, -1 - turn off cache. Default is %d", keystore.DefaultCacheSize))
	flagSet.Bool("pgsql_hex_bytea", false, "Hex format for Postgresql bytea data (deprecated, ignored)")
	flagSet.Bool("pgsql_escape_bytea", false, "Escape format for Postgresql bytea data (deprecated, ignored)")
	flagSet.Bool("acrastruct_wholecell_enable", false, "Acrastruct will stored in whole data cell (deprecated, ignored)")
	flagSet.Bool("acrastruct_injectedcell_enable", false, "Acrastruct may be injected into any place of data cell (deprecated, ignored)")
	flagSet.Bool("ds", false, "Turn on HTTP debug server")
	flagSet.Int("incoming_connection_close_timeout", DefaultAcraServerWaitTimeout, "Time that AcraServer will wait (in seconds) on restart before closing all connections")
	flagSet.Bool("poison_detect_enable", false, "Turn on poison record detection, if server shutdown is disabled, AcraServer logs the poison record detection and returns decrypted data")
	flagSet.Bool("poison_shutdown_enable", false, "On detecting poison record: log about poison record detection, stop and shutdown")
	flagSet.String("poison_run_script_file", "", "On detecting poison record: log about poison record detection, execute script, return decrypted data")
	flagSet.Bool("http_api_enable", false, "Enable HTTP API. Use together with --http_api_tls_transport_enable whenever possible.")
	flagSet.Bool("http_api_tls_transport_enable", false, "Enable HTTPS support for the API. Use together with the --http_api_enable. TLS configuration is the same as in the Acra Proxy. Starting from 0.96.0 the flag value will be true by default.")
	flagSet.Bool("tls_client_id_from_cert", true, "Extract clientID from TLS certificate from application connection. Can't be used with --tls_client_auth=0 or --tls_auth=0")
	flagSet.String("tls_identifier_extractor_type", network.DefaultIdentifierExtractorTypeDistinguishedName, fmt.Sprintf("Decide which field of TLS certificate to use as ClientID (%s). Default is %s.", strings.Join(network.IdentifierExtractorTypesList, "|"), network.IdentifierExtractorTypeDistinguishedName))
	flagSet.String("client_id", "", "Static ClientID used by AcraServer for data protection operations")
	flagSet.String("incoming_connection_string", network.BuildConnectionString(cmd.DefaultAcraServerConnectionProtocol, cmd.DefaultAcraServerHost, cmd.DefaultAcraServerPort, ""), "Connection string like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	flagSet.String("incoming_connection_api_string", network.BuildConnectionString(cmd.DefaultAcraServerConnectionProtocol, cmd.DefaultAcraServerHost, cmd.DefaultAcraServerAPIPort, ""), "Connection string for api like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	flagSet.Bool("sql_parse_on_error_exit_enable", false, "Stop AcraServer execution in case of SQL query parse error. Default is false")
	flagSet.Bool("mysql_enable", false, "Handle MySQL connections")
	flagSet.Bool("postgresql_enable", false, "Handle Postgresql connections (default true)")
	flagSet.String("acracensor_config_file", "", "Path to AcraCensor configuration file")
	flagSet.String("token_db", "", "Path to BoltDB database file to store tokens")
	flagSet.String("encryptor_config_storage_type", config_loader.EncryptoConfigStorageTypeFilesystem, fmt.Sprintf("Encryptor configuration file storage types: <%s", strings.Join(config_loader.SupportedEncryptorConfigStorages, "|")))
	flagSet.Bool("audit_log_enable", false, "Enable audit log functionality")
	flagSet.Bool("v", false, "Log to stderr all INFO, WARNING and ERROR logs")
	flagSet.Bool("d", false, "Log everything to stderr")
	flagSet.Bool("log_to_console", true, "Log to stderr if true")
	flagSet.String("log_to_file", "", "Log to file if path not empty value")

	network.RegisterTLSBaseArgs(flagSet)
	network.RegisterTLSArgsForService(flagSet, false, "", network.ClientNameConstructorFunc())
	network.RegisterTLSArgsForService(flagSet, true, "", network.DatabaseNameConstructorFunc())
	cmd.RegisterRedisKeystoreParameters()
	cmd.RegisterRedisTokenStoreParameters()
	keyloader.RegisterKeyStoreStrategyParameters()
	config_loader.RegisterEncryptorConfigLoaderParameters()
	cmd.RegisterTracingCmdParameters()
	cmd.RegisterJaegerCmdParameters()
}

func realMain() error {
	registerFlags(flag.CommandLine)

	if err := cmd.ParseFlags(flag.CommandLine, os.Args[1:]); err != nil {
		if err == cmd.ErrDumpRequested {
			cmd.DumpConfig(DefaultConfigPath, ServiceName, true)
			os.Exit(0)
		}

		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		return err
	}

	serviceConfig, err := cmd.ParseConfig(DefaultConfigPath, ServiceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse config")
		return err
	}

	argsExtractor := args.NewServiceExtractor(flag.CommandLine, serviceConfig)

	loggingFormat := argsExtractor.GetString("logging_format", "")
	dbHost := argsExtractor.GetString("db_host", "")
	dbPort := argsExtractor.GetInt("db_port", "")
	prometheusAddress := argsExtractor.GetString("incoming_connection_prometheus_metrics_string", "")
	host := argsExtractor.GetString("incoming_connection_host", "")
	port := argsExtractor.GetInt("incoming_connection_port", "")
	apiPort := argsExtractor.GetInt("incoming_connection_api_port", "")
	keysDir := argsExtractor.GetString("keys_dir", "")
	cacheKeystoreOnStart := argsExtractor.GetBool("keystore_cache_on_start_enable", "")
	keysCacheSize := argsExtractor.GetInt("keystore_cache_size", "")
	debugServer := argsExtractor.GetBool("ds", "")
	closeConnectionTimeout := argsExtractor.GetInt("incoming_connection_close_timeout", "")
	detectPoisonRecords := argsExtractor.GetBool("poison_detect_enable", "")
	stopOnPoison := argsExtractor.GetBool("poison_shutdown_enable", "")
	scriptOnPoison := argsExtractor.GetString("poison_run_script_file", "")
	enableHTTPAPI := argsExtractor.GetBool("http_api_enable", "")
	httpAPIUseTLS := argsExtractor.GetBool("http_api_tls_transport_enable", "")
	tlsUseClientIDFromCertificate := argsExtractor.GetBool("tls_client_id_from_cert", "")
	tlsIdentifierExtractorType := argsExtractor.GetString("tls_identifier_extractor_type", "")
	clientID := argsExtractor.GetString("client_id", "")
	acraConnectionString := argsExtractor.GetString("incoming_connection_string", "")
	acraAPIConnectionString := argsExtractor.GetString("incoming_connection_api_string", "")
	sqlParseErrorExitEnable := argsExtractor.GetBool("sql_parse_on_error_exit_enable", "")
	useMysql := argsExtractor.GetBool("mysql_enable", "")
	usePostgresql := argsExtractor.GetBool("postgresql_enable", "")
	censorConfig := argsExtractor.GetString("acracensor_config_file", "")
	boltTokebDB := argsExtractor.GetString("token_db", "")
	encryptorConfigStorageType := argsExtractor.GetString("encryptor_config_storage_type", "")
	enableAuditLog := argsExtractor.GetBool("audit_log_enable", "")
	verbose := argsExtractor.GetBool("v", "")
	debug := argsExtractor.GetBool("d", "")
	logToConsole := argsExtractor.GetBool("log_to_console", "")
	logToFile := argsExtractor.GetString("log_to_file", "")
	network.SetTLSBaseArgs(argsExtractor)

	if os.Getenv(GracefulRestartEnv) == "true" {
		// if process is forked, here we are blocked on reading signal from parent process (via pipe). When signal is read,
		// it means that parent process will not log any messages and now forked process is allowed to start logging. We should
		// wait a bit longer than parent process while closing connections, since there is minimal time-delta on exiting from parent process
		err := waitReadPipe(time.Duration(closeConnectionTimeout+1) * time.Second)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantForkProcess).
				Errorln("Error occurred while reading signal from pipe")
			return err
		}
	}

	// Start customizing logs here (directly after command line arguments parsing)
	formatter := logging.CreateCryptoFormatter(loggingFormat)
	// Set formatter early in order to have consistent format for further logs
	formatter.SetServiceName(ServiceName)
	log.SetFormatter(formatter)

	writer, logFinalize, err := logging.NewWriter(logToConsole, logToFile)
	if err != nil {
		log.WithError(err).Errorln("Can't initialise output writer for logging customization")
		return err
	}
	defer logFinalize()
	log.SetOutput(writer)

	version, err := utils.GetParsedVersion()
	if err != nil {
		log.WithError(err).Errorln("Cannot parse version")
		return err
	}
	log.WithFields(log.Fields{"version": version.String()}).Infof("Starting service %v [pid=%v]", ServiceName, os.Getpid())

	serverConfig, err := common.NewConfig()
	if err != nil {
		log.WithError(err).Errorln("Can't initialize config")
		return err
	}

	serverConfig.TraceToLog = cmd.IsTraceToLogOn()

	cmd.SetupTracing(ServiceName)

	log.Infof("Validating service configuration...")

	serverConfig.SetAcraConnectionString(acraConnectionString)
	if host != cmd.DefaultAcraServerHost || port != cmd.DefaultAcraServerPort {
		serverConfig.SetAcraConnectionString(network.BuildConnectionString("tcp", host, port, ""))
	}
	serverConfig.SetAcraAPIConnectionString(acraAPIConnectionString)
	if apiPort != cmd.DefaultAcraServerAPIPort {
		serverConfig.SetAcraAPIConnectionString(network.BuildConnectionString("tcp", host, apiPort, ""))
	}

	if dbHost == "" {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
			Errorln("db_host is empty: you must specify db_host")
		flag.Usage()
		return err
	}
	serverConfig.SetDBConnectionSettings(dbHost, dbPort)

	if config_loader.IsEncryptorConfigLoaderCLIConfigured(argsExtractor) {
		if err := serverConfig.LoadMapTableSchemaConfig(argsExtractor, encryptorConfigStorageType, useMysql); err != nil {
			log.WithError(err).Errorln("Can't load encryptor config")
			return err
		}
		log.Infoln("Encryptor configuration loaded")
	}

	if err := serverConfig.SetDatabaseType(useMysql, usePostgresql); err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
			Errorln("Can't configure database type")
		return err
	}

	sqlparser.SetDefaultDialect(serverConfig.GetSQLDialect())

	if err := serverConfig.SetCensor(censorConfig); err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSetupError).
			Errorln("Can't setup censor")
		return err
	}

	// now it's stub as default values
	serverConfig.SetDetectPoisonRecords(detectPoisonRecords)
	serverConfig.SetEnableHTTPAPI(enableHTTPAPI)
	serverConfig.SetDebug(debug)
	serverConfig.SetServiceName(ServiceName)
	serverConfig.SetConfigPath(cmd.ConfigPath(DefaultConfigPath))

	log.Infof("Initialising keystore...")
	var keyStore keystore.ServerKeyStore
	if filesystemV2.IsKeyDirectory(keysDir, argsExtractor) {
		keyStore, err = openKeyStoreV2(keysDir, keysCacheSize, argsExtractor)
	} else {
		keyStore, err = openKeyStoreV1(keysDir, keysCacheSize, argsExtractor)
	}
	if err != nil {
		log.WithError(err).Errorln("Can't open keyStore")
		return err
	}

	if cacheKeystoreOnStart {
		if keysCacheSize == keystore.WithoutCache {
			log.Errorln("Can't cache on start with disabled cache")
			os.Exit(1)
		}
		if err := keyStore.CacheOnStart(); err != nil {
			log.WithError(err).Errorln("Failed to cache keystore on start")
			return err
		}
		log.Info("Cached keystore on start successfully")
	}

	serverConfig.SetKeyStore(keyStore)
	log.WithField("path", keysDir).Infof("Keystore init OK")

	if err := crypto.InitRegistry(keyStore); err != nil {
		log.WithError(err).Errorln("Can't initialize crypto registry")
		return err
	}

	var auditLogHandler *logging.AuditLogHandler
	if enableAuditLog {
		auditLogKey, err := keyStore.GetLogSecretKey()
		if err != nil {
			log.WithError(err).Errorln("Can't load logging key")
			return err
		}

		hooks, err := logging.NewHooks(auditLogKey, loggingFormat)
		if err != nil {
			log.WithError(err).Errorln("Can't initialise necessary hooks for logging customization")
			return err
		}
		// zeroing key after initializing crypto-hook
		utils.ZeroizeSymmetricKey(auditLogKey)
		formatter.SetHooks(hooks)

		auditLogHandler, err = logging.NewAuditLogHandler(formatter, writer)
		if err != nil {
			log.WithError(err).Errorln("Can't create audit log handler")
			return err
		}
		// Set updated formatter for audit log
		log.SetFormatter(auditLogHandler)
		defer auditLogHandler.FinalizeChain()
	}

	log.Infof("Configuring transport...")
	serverConfig.SetUseClientIDFromCertificate(tlsUseClientIDFromCertificate)
	if err := serverConfig.SetStaticClientID([]byte(clientID)); err != nil {
		log.WithError(err).Errorln("Cannot be configured static clientID")
		os.Exit(1)
	}

	appSideTLSConfig, err := network.NewTLSConfigByName(argsExtractor, "", "", network.ClientNameConstructorFunc())
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
			Errorln("Configuration error: can't create application TLS config")
		os.Exit(1)
	}

	dbTLSConfig, err := network.NewTLSConfigByName(argsExtractor, "", dbHost, network.DatabaseNameConstructorFunc())
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
			Errorln("Configuration error: can't create database TLS config")
		os.Exit(1)
	}
	if tlsUseClientIDFromCertificate && appSideTLSConfig.ClientAuth == tls.NoClientCert {
		log.Errorln("Cannot be used --tls_client_id_from_cert together with " +
			"--tls_auth=0 or --tls_client_auth=0 due to unnecessary of client's certificate in TLS handshake")
		os.Exit(1)
	}
	idConverter, err := network.NewDefaultHexIdentifierConverter()
	if err != nil {
		log.WithError(err).Errorln("Can't initialize identifier converter")
		os.Exit(1)
	}
	identifierExtractor, err := network.NewIdentifierExtractorByType(tlsIdentifierExtractorType)
	if err != nil {
		log.WithField("type", tlsIdentifierExtractorType).WithError(err).Errorln("Can't initialize identifier extractor")
		os.Exit(1)
	}
	clientIDExtractor, err := network.NewTLSClientIDExtractor(identifierExtractor, idConverter)
	if err != nil {
		log.WithError(err).Errorln("Can't initialize clientID extractor")
		os.Exit(1)
	}
	serverConfig.SetTLSClientIDExtractor(clientIDExtractor)
	// configured TLS wrapper which may be used for communication with app or database
	tlsWrapper, err := network.NewTLSAuthenticationConnectionWrapper(
		tlsUseClientIDFromCertificate, dbTLSConfig, appSideTLSConfig, clientIDExtractor)
	if err != nil {
		log.WithError(err).Errorln("Can't initialize TLS connection wrapper")
		os.Exit(1)
	}

	{
		var httpAPIConnWrapper network.HTTPServerConnectionWrapper
		var err error
		if httpAPIUseTLS {
			if !enableHTTPAPI {
				log.WithField(logging.FieldKeyEventCode, logging.EventCodeGeneral).
					Warningln("--http_api_tls_transport_enable is provided, but the HTTP API server is not configured. Use --http_api_enable to enable it.")
				os.Exit(1)
			}
			httpAPIConnWrapper, err = common.BuildHTTPAPIConnectionWrapper(tlsWrapper, tlsUseClientIDFromCertificate, serverConfig.GetStaticClientID())
		} else {
			if enableHTTPAPI {
				log.WithField(logging.FieldKeyEventCode, logging.EventCodeGeneral).
					Warningln("HTTP API server is used without TLS. Consider using TLS whenever possible.")
				if len(serverConfig.GetStaticClientID()) == 0 {
					log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
						Warning("HTTP API server is configured without TLS, which requires non-empty clientID. Either configure TLS for the HTTP API server, use --client_id option.")
				}
			}
			httpAPIConnWrapper, err = common.BuildHTTPAPIConnectionWrapper(nil, tlsUseClientIDFromCertificate, serverConfig.GetStaticClientID())
		}
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
				Errorln("Can't initialize HTTPAPIConnectionWrapper")
			os.Exit(1)
		}
		serverConfig.HTTPAPIConnectionWrapper = httpAPIConnWrapper
	}

	proxyTLSWrapper := base.NewTLSConnectionWrapper(tlsUseClientIDFromCertificate, tlsWrapper)
	log.WithField("tls_client_id_from_cert", tlsUseClientIDFromCertificate).Infoln("Loaded TLS configuration")

	// here ConnectionWrapper used to establish connection with app via pure net.Conn with known static clientID on server side
	// which ClientID will be used in next steps depends on --tls_client_id_from_cert parameter. If --tls_client_id_from_cert=false
	// then will be used static --client_id otherwise will be extracted from TLS certificate and override static variant
	if (len(serverConfig.GetStaticClientID()) == 0) && !tlsUseClientIDFromCertificate {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
			Errorln("Configuration error: without encryption you must set <client_id> which will be used to connect to AcraServer")
		return err
	}

	log.Debugf("Registering process signal handlers")
	sigHandlerSIGTERM, err := cmd.NewSignalHandler([]os.Signal{os.Interrupt, syscall.SIGTERM})
	if err != nil {
		log.WithError(err).Errorln("Can' initialize signal handler for SIGTERM")
		os.Exit(1)
	}
	errorSignalChannel = sigHandlerSIGTERM.GetChannel()
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantRegisterSignalHandler).
			Errorln("System error: can't register SIGTERM handler")
		return err
	}

	sigHandlerSIGHUP, err := cmd.NewSignalHandler([]os.Signal{syscall.SIGHUP})
	restartSignalsChannel = sigHandlerSIGHUP.GetChannel()
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantRegisterSignalHandler).
			Errorln("System error: can't register SIGHUP handler")
		return err
	}

	// this context is propagated to the SServer which is a main component of the AcraServer service
	// and is used for controlling spawned background goroutines on its level
	mainContext, cancel := context.WithCancel(context.Background())

	// this waitGroup object is used for synchronizing of background goroutines (system signals handlers) that spawned in this main function
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		sigHandlerSIGTERM.RegisterWithContext(mainContext)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		sigHandlerSIGHUP.RegisterWithContext(mainContext)
	}()

	poisonCallbacks := poison.NewCallbackStorage()
	if detectPoisonRecords {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodePoisonRecordDetectionMessage).Infoln("Turned on poison record detection")
		// used to turn off poison record detection which rely on HasCallbacks
		poisonCallbacks.AddCallback(poison.EmptyCallback{})
		if scriptOnPoison != "" {
			poisonCallbacks.AddCallback(poison.NewExecuteScriptCallback(scriptOnPoison))
			serverConfig.SetScriptOnPoison(scriptOnPoison)
			log.WithField("poison_run_script_file", scriptOnPoison).Infoln("Turned on script execution for on detected poison record")
		}
		// should setup "stopOnPoison" as last poison record callback"
		if stopOnPoison {
			poisonCallbacks.AddCallback(&poison.StopCallback{})
			serverConfig.SetStopOnPoison(stopOnPoison)
			log.Infoln("Turned on poison record callback that stops acra-server after poison record detection")
		}
	}

	var tokenStorage pseudonymizationCommon.TokenStorage
	redis := cmd.ParseRedisCLIParametersFromFlags(argsExtractor, "")
	if boltTokebDB != "" {
		log.Infoln("Initialize bolt db storage for tokens")
		db, err := bolt.Open(boltTokebDB, 0600, nil)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize boltdb token storage")
			return err
		}
		defer db.Close()
		tokenStorage = storage.NewBoltDBTokenStorage(db)
		log.Infoln("Initialized bolt db storage for tokens")
	} else if redis.TokensConfigured() {
		log.Infoln("Initialize redis db storage for tokens")
		// if redisTLSConfig = nil then will not be used TLS for Redis
		var redisTLSConfig *tls.Config
		if redis.TLSEnable {
			redisTLSConfig, err = network.NewTLSConfigByName(argsExtractor, "redis", redis.HostPort, network.ClientNameConstructorFunc())
			if err != nil {
				log.WithError(err).Errorln("Can't initialize tls config for redis client")
				return err
			}
		}
		redisClient, err := storage.NewRedisClient(redis.HostPort, redis.Password, redis.DBTokens, redisTLSConfig)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize redis client")
			return err
		}
		tokenStorage, err = storage.NewRedisStorage(redisClient)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize token storage with redis storage")
			return err
		}
		log.Infoln("Initialized redis db storage for tokens")
	} else {
		log.Infoln("Initialize in-memory db storage for tokens")
		tokenStorage, err = storage.NewMemoryTokenStorage()
		if err != nil {
			log.WithError(err).Errorln("Can't initialize token storage in memory")
			return err
		}
		log.Infoln("Initialized in-memory db storage for tokens")
	}

	var sqlParser *sqlparser.Parser

	if sqlParseErrorExitEnable {
		sqlParser = sqlparser.New(sqlparser.ModeStrict)
	} else {
		sqlParser = sqlparser.New(sqlparser.ModeDefault)
	}
	log.Infof("Initialized SQL query parser in %s mode", sqlParser.Mode())

	tokenEncryptor, err := storage.NewSCellEncryptor(keyStore)
	if err != nil {
		log.WithError(err).Errorln("Can't initialize token encryptor")
		return err
	}
	tokenStorage = storage.WrapStorageWithEncryption(tokenStorage, tokenEncryptor)
	tokenizer, err := pseudonymization.NewPseudoanonymizer(tokenStorage)
	if err != nil {
		log.WithError(err).Errorln("Can't initialize tokenizer")
		return err
	}

	var proxyFactory base.ProxyFactory
	proxySetting := base.NewProxySetting(sqlParser, serverConfig.GetTableSchema(), keyStore, proxyTLSWrapper, serverConfig.GetCensor(), poisonCallbacks)
	if useMysql {
		proxyFactory, err = mysql.NewProxyFactory(proxySetting, keyStore, tokenizer)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize proxy for connections")
			return err
		}
	} else {
		proxyFactory, err = postgresql.NewProxyFactory(proxySetting, keyStore, tokenizer)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize proxy for connections")
			return err
		}
	}

	server, err := common.NewEEAcraServerMainComponent(serverConfig, proxyFactory, errorSignalChannel, restartSignalsChannel)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartService).
			Errorf("System error: can't start %s", ServiceName)
		return err
	}

	if os.Getenv(GracefulRestartEnv) == "true" {
		log.Debugf("Will be using %s if configured from WebUI", GracefulRestartEnv)
	}

	if debugServer {
		//start http server for pprof
		debugServerAddress := "127.0.0.1:6060"
		log.Debugf("Starting Debug server on %s", debugServerAddress)

		wg.Add(1)
		go func() {
			defer wg.Done()
			// if mainContext is Done, we should close our Debug server
			debugServer := &http.Server{ReadTimeout: network.DefaultNetworkTimeout, WriteTimeout: network.DefaultNetworkTimeout, Addr: debugServerAddress}
			go func() {
				err := debugServer.ListenAndServe()
				if !errors.Is(err, http.ErrServerClosed) {
					log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartService).
						Errorln("System error: got error from Debug Server")
				}
			}()
			<-mainContext.Done()
			_ = debugServer.Shutdown(context.TODO())
		}()
	}

	if prometheusAddress != "" {
		version, err := utils.GetParsedVersion()
		if err != nil {
			log.WithError(err).Fatal("Invalid version string")
		}
		common.RegisterMetrics(ServiceName, version, utils.EnterpriseEdition)
		_, prometheusHTTPServer, err := cmd.RunPrometheusHTTPHandler(prometheusAddress)
		if err != nil {
			panic(err)
		}
		log.Infof("Configured to send metrics and stats to `incoming_connection_prometheus_metrics_string`")
		stopPrometheusServer := func() {
			log.Infoln("Stop prometheus HTTP exporter")
			if err := prometheusHTTPServer.Close(); err != nil {
				log.WithError(err).Errorln("Error on prometheus server close")
			}
		}
		sigHandlerSIGHUP.AddCallback(stopPrometheusServer)
		sigHandlerSIGTERM.AddCallback(stopPrometheusServer)
	}

	if enableAuditLog {
		// handle SIGUSR1 signal (we use it for force refreshing of audit log chain)
		sigHandlerSIGUSR1 := make(chan os.Signal, 1)

		wg.Add(1)
		go func() {
			defer wg.Done()

			signal.Notify(sigHandlerSIGUSR1, syscall.SIGUSR1)
			for {
				select {
				case <-sigHandlerSIGUSR1:
					log.Infoln("Received incoming SIGUSR1 signal")
					auditLogKey, err := keyStore.GetLogSecretKey()
					if err != nil {
						log.WithError(err).Errorln("Can't fetch log key from keystore")
						// Gracefully shutdown our service according to security-by-default concept.
						// We have a T1658 task that foresees configuration of this behaviour, since for some users
						// it is desirable to continue working on old state of the log key
						server.StopListeners()
						server.Close()
						cancel()
						server.Exit(err)
					}
					auditLogHandler.ResetChain(auditLogKey)
					// zeroing key after resetting chain
					utils.ZeroizeSymmetricKey(auditLogKey)

				case <-mainContext.Done():
					// global shutdown request has been obtained. Just exit from this goroutine
					return
				}
			}
		}()
	}

	// SIGTERM should be handled only once but potentially it may be invoked twice
	// if HTTP API is running simultaneously with SQL queries handler (Start and StartCommands)
	var onceSIGTERM sync.Once
	sigHandlerSIGTERM.AddCallback(func() {
		onceSIGTERM.Do(func() {
			log.Infof("Received incoming SIGTERM or SIGINT signal")
			server.StopListeners()
			server.Close()
			cancel()
			server.Exit(nil)

			log.Infof("Server graceful shutdown completed, bye PID: %v", os.Getpid())
		})
	})

	// we initialize pipeWrite only in SIGHUP handler
	var pipeWrite *os.File
	var onceSIGHUP sync.Once
	sigHandlerSIGHUP.AddCallback(func() {
		onceSIGHUP.Do(func() {
			shutdownCurrentInstance := func(err error) {
				server.Close()
				cancel()
				server.Exit(err)
			}

			log.Infof("Received incoming SIGHUP signal")
			log.Debugf("Stop accepting new connections, waiting until current connections close")

			// Stop accepting requests
			server.StopListeners()

			// Get socket file descriptor to pass it to fork
			var fdACRA, fdAPI uintptr
			fdACRA, err = network.ListenerFileDescriptor(server.ListenerAcra())
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetFileDescriptor).
					Errorln("System error: failed to get acra-socket file descriptor:", err)
				shutdownCurrentInstance(err)
				return
			}
			if enableHTTPAPI {
				fdAPI, err = network.ListenerFileDescriptor(server.ListenerAPI())
				if err != nil {
					log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetFileDescriptor).
						Errorln("System error: failed to get api-socket file descriptor:", err)
					shutdownCurrentInstance(err)
					return
				}
			}

			// Set env flag for forked process
			if err := os.Setenv(GracefulRestartEnv, "true"); err != nil {
				log.WithError(err).Errorf("Unexpected error on os.Setenv, graceful restart won't work. Please check env variables, especially %s", GracefulRestartEnv)
				shutdownCurrentInstance(err)
				return
			}

			// We use inter-process pipe for synchronizing parent process and child forked process.
			// When forked process starts, it blocks on reading signal from pipe that parent process
			// finished with graceful shutdown. This is important for audit log mechanism that requires
			// consistency of log stream
			var pipeRead *os.File
			pipeRead, pipeWrite, err = os.Pipe()
			if err != nil {
				log.WithError(err).Errorln("Can't create inter-process pipe")
				shutdownCurrentInstance(err)
				return
			}

			execSpec := &syscall.ProcAttr{
				Env:   os.Environ(),
				Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd(), fdACRA, fdAPI, pipeRead.Fd()},
			}

			log.Debugf("Forking new process of %s", ServiceName)
			executable, err := os.Executable()
			if err != nil {
				log.WithError(err).Errorln("Can't find full binary path")
				shutdownCurrentInstance(err)
				return
			}
			// Fork new process
			fork, err := syscall.ForkExec(executable, os.Args, execSpec)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantForkProcess).
					WithField("executable", executable).
					Errorln("System error: failed to fork new process", err)
				shutdownCurrentInstance(err)
				return
			}
			log.Infof("%s process forked to PID: %v", ServiceName, fork)

			// Wait a maximum of N seconds for existing connections to finish
			err = server.WaitWithTimeout(time.Duration(closeConnectionTimeout) * time.Second)
			if err == common.ErrWaitTimeout {
				log.Warningf("Server shutdown Timeout: %d active connections will be cut", server.ConnectionsCounter())
			}
			log.Infof("Server graceful restart completed, bye PID: %v", os.Getpid())
			// Stop the old server, all the connections have been closed and the new one is running
			shutdownCurrentInstance(nil)
		})
	})

	log.Infof("Start listening to connections. Current PID: %v", os.Getpid())

	// by default should be false
	sqlparser.SetTokenizerVerbosity(false)
	sqlparser.SetSQLParserErrorVerboseLevel(false)
	if debug {
		log.Infof("Enabling DEBUG log level")
		logging.SetLogLevel(logging.LogDebug)
		sqlparser.SetSQLParserErrorVerboseLevel(true)
		sqlparser.SetTokenizerVerbosity(true)
	} else if verbose {
		log.Infof("Enabling VERBOSE log level")
		logging.SetLogLevel(logging.LogVerbose)
	} else {
		log.Infof("Disabling future logs... Set -v -d to see logs")
		logging.SetLogLevel(logging.LogDiscard)
	}

	if os.Getenv(GracefulRestartEnv) == "true" {
		err = server.StartServerFromFileDescriptor(mainContext, &wg, enableHTTPAPI, DescriptorAcra, DescriptorAPI)
	} else {
		err = server.StartServer(mainContext, &wg, enableHTTPAPI)
	}

	if utils.WaitWithTimeout(&wg, utils.DefaultWaitGroupTimeoutDuration) {
		log.Errorf("Couldn't stop all background goroutines spawned by main function. Exited by timeout")
		return ErrShutdownTimeout
	}

	// write signal for forked process to start logging
	if pipeWrite != nil {
		_, pipeWriteError := pipeWrite.Write([]byte(SignalToStartForkedProcess))
		if pipeWriteError != nil {
			log.WithError(pipeWriteError).Errorf("Couldn't write signal to pipe for forked process")
			return ErrPipeWrite
		}
	}
	return err
}

func waitReadPipe(timeoutDuration time.Duration) error {
	// unblock our pipe in order to use deadline for Read operation. It is important to call this before creating *os.File object from file descriptor
	err := syscall.SetNonblock(DescriptorPipe, true)
	if err != nil {
		return err
	}
	pipeRead := os.NewFile(DescriptorPipe, "/tmp/acra-server_interprocess_pipe")
	defer func() {
		// it seems that potential errors from closing the pipe will not affect further operation of our service, so just skip them
		pipeRead.Close()
	}()

	// here we use deadlines from IO as a timeout. Read operation will be blocked and will fail
	// in case if parent process for some reasons wouldn't write correct signal to pipe,
	// so it is enough for us to call try reading just once, assuming that in happy case
	// reading from pipe by forked process will be performed after writing to pipe by its
	// parent. Otherwise Read will fail with ErrDeadlineExceeded
	err = pipeRead.SetDeadline(time.Now().Add(timeoutDuration))
	if err != nil {
		return err
	}
	var signalToStartForkedProcess bytes.Buffer
	_, err = signalToStartForkedProcess.ReadFrom(pipeRead)
	if err != nil {
		return err
	}
	if !strings.EqualFold(signalToStartForkedProcess.String(), SignalToStartForkedProcess) {
		return ErrPipeReadWrongSignal
	}
	return nil
}

func openKeyStoreV1(output string, cacheSize int, extractor *args.ServiceExtractor) (keystore.ServerKeyStore, error) {
	var keyStoreEncryptor keystore.KeyEncryptor

	keyStoreEncryptor, err := keyloader.CreateKeyEncryptor(extractor, "")
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore KeyEncryptor")
		return nil, err
	}

	keyStore := filesystem.NewCustomFilesystemKeyStore()
	keyStore.KeyDirectory(output)
	keyStore.CacheSize(cacheSize)
	keyStore.Encryptor(keyStoreEncryptor)

	redis := cmd.ParseRedisCLIParameters(extractor)
	cmd.ValidateRedisCLIOptions(redis)

	if redis.KeysConfigured() {
		redisOptions, err := redis.KeysOptions(extractor)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
				Errorln("Can't get Redis options")
			return nil, err
		}
		keyStorage, err := filesystem.NewRedisStorage(redis.HostPort, redis.Password, redis.DBKeys, redisOptions.TLSConfig)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
				Errorln("Can't initialize Redis client")
			return nil, err
		}
		keyStore.Storage(keyStorage)
	}
	keyStoreV1, err := keyStore.Build()
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore")
		return nil, err
	}
	return keyStoreV1, nil
}

func openKeyStoreV2(keyDirPath string, cacheSize int, extractor *args.ServiceExtractor) (keystore.ServerKeyStore, error) {
	if cacheSize != keystore.WithoutCache {
		return nil, keystore.ErrCacheIsNotSupportedV2
	}

	keyStoreSuite, err := keyloader.CreateKeyEncryptorSuite(extractor, "")
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore keyStoreSuite")
		return nil, err
	}

	var backend filesystemBackendV2.Backend

	redis := cmd.ParseRedisCLIParameters(extractor)
	cmd.ValidateRedisCLIOptions(redis)

	if redis.KeysConfigured() {
		redisOptions, err := redis.KeysOptions(extractor)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize Redis options")
			os.Exit(1)
		}
		config := &filesystemBackendV2.RedisConfig{
			RootDir: keyDirPath,
			Options: redisOptions,
		}
		backend, err = filesystemBackendV2.OpenRedisBackend(config)
		if err != nil {
			log.WithError(err).Error("Cannot connect to Redis keystore")
			return nil, err
		}
	} else {
		backend, err = filesystemBackendV2.OpenDirectoryBackend(keyDirPath)
		if err != nil {
			log.WithError(err).Error("Cannot open key directory")
			return nil, err
		}
	}
	keyDirectory, err := filesystemV2.CustomKeyStore(backend, keyStoreSuite)
	if err != nil {
		log.WithError(err).Error("Failed to initialize key directory")
		return nil, err
	}
	return keystoreV2.NewServerKeyStore(keyDirectory), nil
}
