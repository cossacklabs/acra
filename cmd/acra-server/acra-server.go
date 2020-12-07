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
	"context"
	"crypto/tls"
	"flag"
	"net/http"
	_ "net/http/pprof"
	"os"
	"syscall"
	"time"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/cmd/acra-server/common"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/mysql"
	"github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/sqlparser"
	mysqlDialect "github.com/cossacklabs/acra/sqlparser/dialect/mysql"
	pgDialect "github.com/cossacklabs/acra/sqlparser/dialect/postgresql"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

var restartSignalsChannel chan os.Signal
var errorSignalChannel chan os.Signal
var authPath *string

// Constants used by AcraServer.
const (
	defaultAcraserverWaitTimeout = 10
	gracefulEnv                  = "GRACEFUL_RESTART"
	descriptorAcra               = 3
	descriptorAPI                = 4
	ServiceName                  = "acra-server"
)

// defaultConfigPath relative path to config which will be parsed as default
var defaultConfigPath = utils.GetConfigPathByName(ServiceName)

const tlsAuthNotSet = -1

func main() {
	loggingFormat := flag.String("logging_format", "plaintext", "Logging format: plaintext, json or CEF")
	dbHost := flag.String("db_host", "", "Host to db")
	dbPort := flag.Int("db_port", 5432, "Port to db")

	prometheusAddress := flag.String("incoming_connection_prometheus_metrics_string", "", "URL (tcp://host:port) which will be used to expose Prometheus metrics (<URL>/metrics address to pull metrics)")

	host := flag.String("incoming_connection_host", cmd.DefaultAcraServerHost, "Host for AcraServer")
	port := flag.Int("incoming_connection_port", cmd.DefaultAcraServerPort, "Port for AcraServer")
	apiPort := flag.Int("incoming_connection_api_port", cmd.DefaultAcraServerAPIPort, "Port for AcraServer for HTTP API")

	keysDir := flag.String("keys_dir", keystore.DefaultKeyDirShort, "Folder from which will be loaded keys")
	keysCacheSize := flag.Int("keystore_cache_size", keystore.InfiniteCacheSize, "Maximum number of keys stored in in-memory LRU cache in encrypted form. 0 - no limits, -1 - turn off cache")

	_ = flag.Bool("pgsql_hex_bytea", false, "Hex format for Postgresql bytea data (deprecated, ignored)")
	flag.Bool("pgsql_escape_bytea", false, "Escape format for Postgresql bytea data (deprecated, ignored)")

	secureSessionID := flag.String("securesession_id", "acra_server", "Id that will be sent in secure session")

	flag.Bool("acrastruct_wholecell_enable", true, "Acrastruct will stored in whole data cell")
	injectedcell := flag.Bool("acrastruct_injectedcell_enable", false, "Acrastruct may be injected into any place of data cell")

	debugServer := flag.Bool("ds", false, "Turn on HTTP debug server")
	closeConnectionTimeout := flag.Int("incoming_connection_close_timeout", defaultAcraserverWaitTimeout, "Time that AcraServer will wait (in seconds) on restart before closing all connections")

	detectPoisonRecords := flag.Bool("poison_detect_enable", true, "Turn on poison record detection, if server shutdown is disabled, AcraServer logs the poison record detection and returns decrypted data")
	stopOnPoison := flag.Bool("poison_shutdown_enable", false, "On detecting poison record: log about poison record detection, stop and shutdown")
	scriptOnPoison := flag.String("poison_run_script_file", "", "On detecting poison record: log about poison record detection, execute script, return decrypted data")

	withZone := flag.Bool("zonemode_enable", false, "Turn on zone mode")
	enableHTTPAPI := flag.Bool("http_api_enable", false, "Enable HTTP API")

	useTLS := flag.Bool("acraconnector_tls_transport_enable", false, "Use tls to encrypt transport between AcraServer and AcraConnector/client")
	tlsKey := flag.String("tls_key", "", "Path to private key that will be used in AcraServer's TLS handshake with AcraConnector as server's key and database as client's key")
	tlsCert := flag.String("tls_cert", "", "Path to tls certificate")
	tlsCA := flag.String("tls_ca", "", "Path to additional CA certificate for AcraConnector and database certificate validation")
	tlsAuthType := flag.Int("tls_auth", int(tls.RequireAndVerifyClientCert), "Set authentication mode that will be used in TLS connection with AcraConnector and database. Values in range 0-4 that set auth type (https://golang.org/pkg/crypto/tls/#ClientAuthType). Default is tls.RequireAndVerifyClientCert")
	tlsClientAuthType := flag.Int("tls_client_auth", tlsAuthNotSet, "Set authentication mode that will be used in TLS connection with AcraConnector. Overrides the \"tls_auth\" setting.")
	tlsClientCA := flag.String("tls_client_ca", "", "Path to additional CA certificate for AcraConnector certificate validation (setup if AcraConnector certificate CA is different from database certificate CA)")
	tlsClientCert := flag.String("tls_client_cert", "", "Path to server TLS certificate presented to AcraConnectors (overrides \"tls_cert\")")
	tlsClientKey := flag.String("tls_client_key", "", "Path to private key of the TLS certificate presented to AcraConnectors (see \"tls_client_cert\")")
	tlsDbAuthType := flag.Int("tls_database_auth", tlsAuthNotSet, "Set authentication mode that will be used in TLS connection with database. Overrides the \"tls_auth\" setting.")
	tlsDbCA := flag.String("tls_database_ca", "", "Path to additional CA certificate for database certificate validation (setup if database certificate CA is different from AcraConnector certificate CA)")
	tlsDbSNI := flag.String("tls_database_sni", "", "Expected Server Name (SNI) from database")
	tlsDbSNIOld := flag.String("tls_db_sni", "", "Expected Server Name (SNI) from database (deprecated, use \"tls_database_sni\" instead)")
	tlsDbCert := flag.String("tls_database_cert", "", "Path to client TLS certificate shown to database during TLS handshake (overrides \"tls_cert\")")
	tlsDbKey := flag.String("tls_database_key", "", "Path to private key of the TLS certificate used to connect to database (see \"tls_database_cert\")")
	tlsUseClientIDFromCertificate := flag.Bool("tls_client_id_from_cert", false, "Use certificate info as clientID for encryption/decryption when used. Use certificate from connector's connection if acraconnector_tls_transport_enable used or from client's connection if acraconnector_transport_encryption_disable used")
	noEncryptionTransport := flag.Bool("acraconnector_transport_encryption_disable", false, "Use raw transport (tcp/unix socket) between AcraServer and AcraConnector/client (don't use this flag if you not connect to database with SSL/TLS")
	clientID := flag.String("client_id", "", "Expected client ID of AcraConnector in mode without encryption")
	acraConnectionString := flag.String("incoming_connection_string", network.BuildConnectionString(cmd.DefaultAcraServerConnectionProtocol, cmd.DefaultAcraServerHost, cmd.DefaultAcraServerPort, ""), "Connection string like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	acraAPIConnectionString := flag.String("incoming_connection_api_string", network.BuildConnectionString(cmd.DefaultAcraServerConnectionProtocol, cmd.DefaultAcraServerHost, cmd.DefaultAcraServerAPIPort, ""), "Connection string for api like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	authPath = flag.String("auth_keys", cmd.DefaultAcraServerAuthPath, "Path to basic auth passwords. To add user, use: `./acra-authmanager --set --user <user> --pwd <pwd>`")

	useMysql := flag.Bool("mysql_enable", false, "Handle MySQL connections")
	usePostgresql := flag.Bool("postgresql_enable", false, "Handle Postgresql connections (default true)")
	censorConfig := flag.String("acracensor_config_file", "", "Path to AcraCensor configuration file")

	encryptorConfig := flag.String("encryptor_config_file", "", "Path to Encryptor configuration file")

	cmd.RegisterTracingCmdParameters()
	cmd.RegisterJaegerCmdParameters()

	verbose := flag.Bool("v", false, "Log to stderr all INFO, WARNING and ERROR logs")
	debug := flag.Bool("d", false, "Log everything to stderr")

	err := cmd.Parse(defaultConfigPath, ServiceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}

	// Start customizing logs here (directly after command line arguments parsing)
	formatter := logging.CreateFormatter(*loggingFormat)
	formatter.SetServiceName(ServiceName)
	log.SetOutput(os.Stderr)

	log.WithField("version", utils.VERSION).Infof("Starting service %v [pid=%v]", ServiceName, os.Getpid())

	config, err := common.NewConfig()
	if err != nil {
		log.WithError(err).Errorln("Can't initialize config")
		os.Exit(1)
	}

	config.TraceToLog = cmd.IsTraceToLogOn()

	cmd.SetupTracing(ServiceName)

	log.Infof("Validating service configuration...")
	cmd.ValidateClientID(*secureSessionID)

	config.SetAcraConnectionString(*acraConnectionString)
	if *host != cmd.DefaultAcraServerHost || *port != cmd.DefaultAcraServerPort {
		config.SetAcraConnectionString(network.BuildConnectionString("tcp", *host, *port, ""))
	}
	config.SetAcraAPIConnectionString(*acraAPIConnectionString)
	if *apiPort != cmd.DefaultAcraServerAPIPort {
		config.SetAcraAPIConnectionString(network.BuildConnectionString("tcp", *host, *apiPort, ""))
	}

	if *dbHost == "" {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
			Errorln("db_host is empty: you must specify db_host")
		flag.Usage()
		os.Exit(1)
	}
	config.SetDBConnectionSettings(*dbHost, *dbPort)

	if *encryptorConfig != "" {
		log.Infof("Load encryptor configuration from %s ...", *encryptorConfig)
		if err = config.LoadMapTableSchemaConfig(*encryptorConfig); err != nil {
			log.WithError(err).Errorln("Can't load encryptor config")
			os.Exit(1)
		}
		log.Infoln("Encryptor configuration loaded")
	}

	if err = config.SetDatabaseType(*useMysql, *usePostgresql); err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
			Errorln("Can't configure database type")
		os.Exit(1)
	}

	if err = config.SetCensor(*censorConfig); err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSetupError).
			Errorln("Can't setup censor")
		os.Exit(1)
	}

	// now it's stub as default values
	config.SetDetectPoisonRecords(*detectPoisonRecords)
	config.SetWithZone(*withZone)
	config.SetWholeMatch(!(*injectedcell))
	config.SetEnableHTTPAPI(*enableHTTPAPI)
	config.SetDebug(*debug)
	config.SetAuthDataPath(*authPath)
	config.SetServiceName(ServiceName)
	config.SetConfigPath(cmd.ConfigPath(defaultConfigPath))

	log.Infof("Initialising keystore...")
	var keyStore keystore.ServerKeyStore
	if filesystemV2.IsKeyDirectory(*keysDir) {
		keyStore = openKeyStoreV2(*keysDir)
	} else {
		keyStore = openKeyStoreV1(*keysDir, *keysCacheSize)
	}
	config.SetKeyStore(keyStore)
	log.Infof("Keystore init OK")

	log.Infof("Configuring transport...")
	var proxyTLSWrapper base.TLSConnectionWrapper
	var tlsWrapper network.ConnectionWrapper
	var clientTLSConfig, dbTLSConfig *tls.Config
	if *useTLS || *tlsKey != "" {
		// Use common TLS settings, unless the user requests specific ones
		if *tlsClientCA == "" {
			*tlsClientCA = *tlsCA
		}
		if *tlsClientAuthType == tlsAuthNotSet {
			*tlsClientAuthType = *tlsAuthType
		}
		if *tlsClientCert == "" {
			*tlsClientCert = *tlsCert
		}
		if *tlsClientKey == "" {
			*tlsClientKey = *tlsKey
		}
		clientTLSConfig, err = network.NewTLSConfig("", *tlsClientCA, *tlsClientKey, *tlsClientCert, tls.ClientAuthType(*tlsClientAuthType))
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
				Errorln("Configuration error: can't create AcraConnector TLS config")
			os.Exit(1)
		}
		// Use common TLS settings, unless the user requests specific ones.
		// Also handle deprecated options.
		if *tlsDbCA == "" {
			*tlsDbCA = *tlsCA
		}
		if *tlsDbAuthType == tlsAuthNotSet {
			*tlsDbAuthType = *tlsAuthType
		}
		if *tlsDbSNI == "" && *tlsDbSNIOld != "" {
			*tlsDbSNI = *tlsDbSNIOld
		}
		if *tlsDbCert == "" {
			*tlsDbCert = *tlsCert
		}
		if *tlsDbKey == "" {
			*tlsDbKey = *tlsKey
		}
		dbTLSConfig, err = network.NewTLSConfig(network.SNIOrHostname(*tlsDbSNI, *dbHost), *tlsDbCA, *tlsDbKey, *tlsDbCert, tls.ClientAuthType(*tlsDbAuthType))
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
				Errorln("Configuration error: can't create database TLS config")
			os.Exit(1)
		}
		idConverter, err := network.NewDefaultHexIdentifierConverter()
		if err != nil {
			log.WithError(err).Errorln("Can't initialize identifier converter")
			os.Exit(1)
		}
		tlsWrapper, err = network.NewTLSAuthenticationConnectionWrapper(dbTLSConfig, clientTLSConfig, network.CommonNameExtractor{}, idConverter)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize TLS connection wrapper")
			os.Exit(1)
		}
		useForClientID := *tlsUseClientIDFromCertificate && *noEncryptionTransport
		proxyTLSWrapper = base.NewTLSConnectionWrapper(useForClientID, tlsWrapper)
		log.WithField("use_client_id_from_cert", useForClientID).Infoln("Loaded TLS configuration")
	}
	if *useTLS {
		if *tlsUseClientIDFromCertificate{
			config.ConnectionWrapper = tlsWrapper
			log.Println("Selecting transport: use TLS transport wrapper with clientID from certificates")
		} else {
			log.Println("Selecting transport: use TLS transport wrapper with static clientID")
			config.ConnectionWrapper, err = network.NewTLSConnectionWrapper([]byte(*clientID), clientTLSConfig)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
					Errorln("Configuration error: can't initialise TLS connection wrapper")
				os.Exit(1)
			}
		}
	} else if *noEncryptionTransport {
		config.SetWithConnector(false)
		if (*clientID == "" && !*withZone) && *tlsKey == "" {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
				Errorln("Configuration error: without zone mode and without encryption you must set <client_id> which will be used to connect from AcraConnector to AcraServer")
			os.Exit(1)
		}
		log.Infof("Selecting transport: use raw transport wrapper")
		config.ConnectionWrapper = &network.RawConnectionWrapper{ClientID: []byte(*clientID)}
	} else {
		log.Infof("Selecting transport: use Secure Session transport wrapper")
		config.ConnectionWrapper, err = network.NewSecureSessionConnectionWrapper([]byte(*secureSessionID), keyStore)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
				Errorln("Configuration error: can't initialize secure session connection wrapper")
			os.Exit(1)
		}
	}

	log.Debugf("Registering process signal handlers")
	sigHandlerSIGTERM, err := cmd.NewSignalHandler([]os.Signal{os.Interrupt, syscall.SIGTERM})
	errorSignalChannel = sigHandlerSIGTERM.GetChannel()
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantRegisterSignalHandler).
			Errorln("System error: can't register SIGTERM handler")
		os.Exit(1)
	}

	sigHandlerSIGHUP, err := cmd.NewSignalHandler([]os.Signal{syscall.SIGHUP})
	restartSignalsChannel = sigHandlerSIGHUP.GetChannel()
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantRegisterSignalHandler).
			Errorln("System error: can't register SIGHUP handler")
		os.Exit(1)
	}

	poisonCallbacks := base.NewPoisonCallbackStorage()
	if *scriptOnPoison != "" {
		poisonCallbacks.AddCallback(base.NewExecuteScriptCallback(*scriptOnPoison))
		config.SetScriptOnPoison(*scriptOnPoison)
	}
	// should setup "stopOnPoison" as last poison record callback"
	if *stopOnPoison {
		poisonCallbacks.AddCallback(&base.StopCallback{})
		config.SetStopOnPoison(*stopOnPoison)
	}

	decryptorSetting := base.NewDecryptorSetting(config.GetWithZone(), config.GetWholeMatch(), *detectPoisonRecords, poisonCallbacks, keyStore)
	var decryptorFactory base.DecryptorFactory
	var proxyFactory base.ProxyFactory
	if *useMysql {
		decryptorFactory = mysql.NewMysqlDecryptorFactory(decryptorSetting)
		proxyFactory, err = mysql.NewProxyFactory(base.NewProxySetting(decryptorFactory, config.GetTableSchema(), keyStore, proxyTLSWrapper, config.GetCensor()))
		if err != nil {
			log.WithError(err).Errorln("Can't initialize proxy for connections")
			os.Exit(1)
		}
		sqlparser.SetDefaultDialect(mysqlDialect.NewMySQLDialect())
	} else {
		decryptorFactory = postgresql.NewDecryptorFactory(decryptorSetting)
		proxyFactory, err = postgresql.NewProxyFactory(base.NewProxySetting(decryptorFactory, config.GetTableSchema(), keyStore, proxyTLSWrapper, config.GetCensor()))
		if err != nil {
			log.WithError(err).Errorln("Can't initialize proxy for connections")
			os.Exit(1)
		}
		sqlparser.SetDefaultDialect(pgDialect.NewPostgreSQLDialect())
	}

	server, err := common.NewServer(config, proxyFactory, errorSignalChannel, restartSignalsChannel)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartService).
			Errorf("System error: can't start %s", ServiceName)
		panic(err)
	}

	if os.Getenv(gracefulEnv) == "true" {
		log.Debugf("Will be using GRACEFUL_RESTART if configured from WebUI")
	}

	if *debugServer {
		//start http server for pprof
		debugServerAddress := "127.0.0.1:6060"
		log.Debugf("Starting Debug server on %s", debugServerAddress)
		go func() {
			debugServer := &http.Server{ReadTimeout: network.DefaultNetworkTimeout, WriteTimeout: network.DefaultNetworkTimeout, Addr: debugServerAddress}
			err := debugServer.ListenAndServe()
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartService).
					Errorln("System error: got error from Debug Server")
			}
		}()
	}

	if *prometheusAddress != "" {
		version, err := utils.GetParsedVersion()
		if err != nil {
			log.WithError(err).Fatal("Invalid version string")
		}
		common.RegisterMetrics(ServiceName, version, utils.CommunityEdition)
		_, prometheusHTTPServer, err := cmd.RunPrometheusHTTPHandler(*prometheusAddress)
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

	sigHandlerSIGTERM.AddCallback(func() {
		log.Infof("Received incoming SIGTERM or SIGINT signal")
		log.Debugf("Stop accepting new connections, waiting until current connections close")
		// Stop accepting new connections
		server.StopListeners()
		// Wait a maximum of N seconds for existing connections to finish
		err := server.WaitWithTimeout(time.Duration(*closeConnectionTimeout) * time.Second)
		if err == common.ErrWaitTimeout {
			log.Warningf("Server shutdown Timeout: %d active connections will be cut", server.ConnectionsCounter())
			server.Close()
			os.Exit(1)
		}
		server.Close()
		log.Infof("Server graceful shutdown completed, bye PID: %v", os.Getpid())
		os.Exit(0)
	})
	go sigHandlerSIGTERM.Register()

	sigHandlerSIGHUP.AddCallback(func() {
		log.Infof("Received incoming SIGHUP signal")
		log.Debugf("Stop accepting new connections, waiting until current connections close")

		// Stop accepting requests
		server.StopListeners()

		// Get socket file descriptor to pass it to fork
		var fdACRA, fdAPI uintptr
		fdACRA, err = network.ListenerFileDescriptor(server.ListenerAcra())
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetFileDescriptor).
				Fatalln("System error: failed to get acra-socket file descriptor:", err)
		}
		if *withZone || *enableHTTPAPI {
			fdAPI, err = network.ListenerFileDescriptor(server.ListenerAPI())
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetFileDescriptor).
					Fatalln("System error: failed to get api-socket file descriptor:", err)
			}
		}

		// Set env flag for forked process
		if err := os.Setenv(gracefulEnv, "true"); err != nil {
			log.WithError(err).Errorln("Unexpected error on os.Setenv, graceful restart won't work. Please check env variables, especially gracefulEnv")
		}
		execSpec := &syscall.ProcAttr{
			Env:   os.Environ(),
			Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd(), fdACRA, fdAPI},
		}

		log.Debugf("Forking new process of %s", ServiceName)

		// Fork new process
		var fork, err = syscall.ForkExec(os.Args[0], os.Args, execSpec)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantForkProcess).
				Fatalln("System error: failed to fork new process", err)
		}
		log.Infof("%s process forked to PID: %v", ServiceName, fork)

		// Wait a maximum of N seconds for existing connections to finish
		err = server.WaitWithTimeout(time.Duration(*closeConnectionTimeout) * time.Second)
		if err == common.ErrWaitTimeout {
			log.Warningf("Server shutdown Timeout: %d active connections will be cut", server.ConnectionsCounter())
			os.Exit(0)
		}
		log.Infof("Server graceful restart completed, bye PID: %v", os.Getpid())
		// Stop the old server, all the connections have been closed and the new one is running
		os.Exit(0)
	})

	log.Infof("Start listening to connections. Current PID: %v", os.Getpid())

	if *debug {
		log.Infof("Enabling DEBUG log level")
		logging.SetLogLevel(logging.LogDebug)
	} else if *verbose {
		log.Infof("Enabling VERBOSE log level")
		logging.SetLogLevel(logging.LogVerbose)
	} else {
		log.Infof("Disabling future logs... Set -v -d to see logs")
		logging.SetLogLevel(logging.LogDiscard)
	}

	ctx := context.Background()
	if os.Getenv(gracefulEnv) == "true" {
		if *withZone || *enableHTTPAPI {
			go server.StartCommandsFromFileDescriptor(ctx, descriptorAPI)
		}
		go server.StartFromFileDescriptor(ctx, descriptorAcra)
	} else {
		if *withZone || *enableHTTPAPI {
			go server.StartCommands(ctx)
		}
		go server.Start(ctx)
	}

	// on sighup we run callback that stop all listeners (that stop background goroutine of server.Start())
	// and try to restart acra-server and only after that exits
	sigHandlerSIGHUP.Register()
}

func openKeyStoreV1(keysDir string, cacheSize int) keystore.ServerKeyStore {
	masterKey, err := keystore.GetMasterKeyFromEnvironment()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master key")
		os.Exit(1)
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithError(err).Errorln("Can't init scell encryptor")
		os.Exit(1)
	}
	keyStore, err := filesystem.NewFileSystemKeyStoreWithCacheSize(keysDir, scellEncryptor, cacheSize)
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
			Errorln("Can't initialise keystore")
		os.Exit(1)
	}
	return keyStore
}

func openKeyStoreV2(keyDirPath string) keystore.ServerKeyStore {
	encryption, signature, err := keystoreV2.GetMasterKeysFromEnvironment()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master key")
		os.Exit(1)
	}
	suite, err := keystoreV2.NewSCellSuite(encryption, signature)
	if err != nil {
		log.WithError(err).Error("failed to initialize Secure Cell crypto suite")
		os.Exit(1)
	}
	keyDir, err := filesystemV2.OpenDirectoryRW(keyDirPath, suite)
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
			WithField("path", keyDirPath).Error("cannot open key directory")
		os.Exit(1)
	}
	return keystoreV2.NewServerKeyStore(keyDir)
}
