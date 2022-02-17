/*
Copyright 2020, Cossack Labs Limited

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

// Package main is entry point for AcraTranslator service. AcraTranslator is a lightweight server that receives
// AcraStructs and returns the decrypted data. This element of Acra is necessary in the use-cases
// when an application stores encrypted data as separate blobs (files that are not in a database - i.e.
// in the S3 bucket, local file storage, etc.).
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	_ "github.com/cossacklabs/acra/cmd/acra-translator/docs"
	"github.com/cossacklabs/acra/cmd/acra-translator/grpc_api"
	"github.com/cossacklabs/acra/cmd/acra-translator/server"
	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/keystore/keyloader/hashicorp"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystem2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	filesystemBackendV2CE "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/acra/pseudonymization"
	common2 "github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/cossacklabs/acra/pseudonymization/storage"
	"github.com/cossacklabs/acra/utils"
	bolt "go.etcd.io/bbolt"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// Constants handy for AcraTranslator.
const (
	ServiceName                      = "acra-translator"
	DefaultAcraTranslatorWaitTimeout = 10
	GracefulRestartEnv               = "GRACEFUL_RESTART"
	SignalToStartForkedProcess       = "forked process is allowed to continue"

	// We use this values as a file descriptors pointers on SIGHUP signal processing.
	// We definitely know (because we implement this), that new forked process starts
	// with three descriptors in mind - stdin (0), stdout (1), stderr(2). And then we
	// use HTTP (3), gRPC (4) and PIPE (5) descriptors. Take a look at callback function
	// that is called on SIGHUP event for more details
	DescriptorHTTP = 3
	DescriptorGRPC = 4
	DescriptorPipe = 5
	tlsAuthNotSet  = -1
)

// DefaultConfigPath relative path to config which will be parsed as default
var DefaultConfigPath = utils.GetConfigPathByName(ServiceName)

// @title Acra-Translator
// @description AcraTranslator is a lightweight server that receives AcraStructs/AcraBlocks and returns the decrypted data
// @termsOfService https://www.cossacklabs.com/acra/

// @contact.name Cossack Labs dev team
// @contact.url cossacklabs.com
// @contact.email dev@cossacklabs.com

// @license.name Acra Evaluation license
// @license.url https://www.cossacklabs.com/acra/

// @BasePath /v2
func main() {
	err := realMain()
	if err != nil {
		os.Exit(1)
	}
}

// ErrShutdownTimeout occurs if we can't perform correct exit from realMain function (when we can't stop background goroutines used to handle system signals)
var ErrShutdownTimeout = errors.New("can't correctly stop all background goroutines on main function level")

// ErrPipeWrite occurs if we can't write to inter-process pipe (that we use for forked and parent processes synchronization upon SIGHUP handling)
var ErrPipeWrite = errors.New("can't write exit signal to pipe")

// ErrPipeReadWrongSignal occurs if we read unexpected signal from pipe between parent and forked processes
var ErrPipeReadWrongSignal = errors.New("wrong signal has been read from pipe")

func realMain() error {
	config := common.NewConfig()
	loggingFormat := flag.String("logging_format", "plaintext", "Logging format: plaintext, json or CEF")

	incomingConnectionHTTPString := flag.String("incoming_connection_http_string", "", "Connection string for HTTP transport like http://0.0.0.0:9595")
	incomingConnectionGRPCString := flag.String("incoming_connection_grpc_string", "", "Default option: connection string for gRPC transport like grpc://0.0.0.0:9696")

	keysDir := flag.String("keys_dir", keystore.DefaultKeyDirShort, "Folder from which will be loaded keys")
	cacheKeystoreOnStart := flag.Bool("keystore_cache_on_start_enable", true, "Load all keys to cache on start")
	keysCacheSize := flag.Int("keystore_cache_size", keystore.DefaultCacheSize, fmt.Sprintf("Maximum number of keys stored in in-memory LRU cache in encrypted form. 0 - no limits, -1 - turn off cache. Default is %d", keystore.DefaultCacheSize))

	detectPoisonRecords := flag.Bool("poison_detect_enable", false, "Turn on poison record detection, if server shutdown is disabled, AcraTranslator logs the poison record detection and returns error")
	stopOnPoison := flag.Bool("poison_shutdown_enable", false, "On detecting poison record: log about poison record detection, stop and shutdown")
	scriptOnPoison := flag.String("poison_run_script_file", "", "On detecting poison record: log about poison record detection, execute script, return decrypted data")

	closeConnectionTimeout := flag.Int("incoming_connection_close_timeout", DefaultAcraTranslatorWaitTimeout, "Time that AcraTranslator will wait (in seconds) on stop signal before closing all connections")

	prometheusAddress := flag.String("incoming_connection_prometheus_metrics_string", "", "URL which will be used to expose Prometheus metrics (use <URL>/metrics address to pull metrics)")
	boltTokenbDB := flag.String("token_db", "", "Path to BoltDB database file to store tokens")
	cmd.RegisterRedisKeyStoreParameters()
	cmd.RegisterRedisTokenStoreParameters()

	tlsIdentifierExtractorType := flag.String("tls_identifier_extractor_type", network.IdentifierExtractorTypeDistinguishedName, fmt.Sprintf("Decide which field of TLS certificate to use as ClientID (%s). Default is %s.", strings.Join(network.IdentifierExtractorTypesList, "|"), network.IdentifierExtractorTypeDistinguishedName))
	useClientIDFromConnection := flag.Bool("acratranslator_client_id_from_connection_enable", false, "Use clientID from TLS certificates or secure session handshake instead directly passed values in gRPC methods")
	enableAuditLog := flag.Bool("audit_log_enable", false, "Enable audit log functionality")

	hashicorp.RegisterVaultCLIParameters()
	cmd.RegisterTracingCmdParameters()
	cmd.RegisterJaegerCmdParameters()
	logging.RegisterCLIArgs()
	network.RegisterTLSBaseArgs()

	verbose := flag.Bool("v", false, "Log to stderr all INFO, WARNING and ERROR logs")
	debug := flag.Bool("d", false, "Log everything to stderr")

	err := cmd.Parse(DefaultConfigPath, ServiceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		return err
	}

	if os.Getenv(GracefulRestartEnv) == "true" {
		// if process is forked, here we are blocked on reading signal from parent process (via pipe). When signal is read,
		// it means that parent process will not log any messages and now forked process is allowed to start logging. We should
		// wait a bit longer than parent process while closing connections, since there is minimal time-delta on exiting from parent process
		err := waitReadPipe(time.Duration(*closeConnectionTimeout+1) * time.Second)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantForkProcess).
				Errorln("Error occurred while reading signal from pipe")
			return err
		}
	}

	// Start customizing logs here (directly after command line arguments parsing)
	formatter := logging.CreateCryptoFormatter(*loggingFormat)
	// Set formatter early in order to have consistent format for further logs
	formatter.SetServiceName(ServiceName)
	log.SetFormatter(formatter)

	writer, logFinalize, err := logging.NewWriter()
	if err != nil {
		log.WithError(err).Errorln("Can't initialise output writer for logging customization")
		return err
	}
	defer logFinalize()
	log.SetOutput(writer)

	log.WithField("version", utils.VERSION).Infof("Starting service %v [pid=%v]", ServiceName, os.Getpid())
	log.Infof("Validating service configuration...")
	if len(*incomingConnectionHTTPString) == 0 && len(*incomingConnectionGRPCString) == 0 {
		*incomingConnectionGRPCString = network.BuildConnectionString(network.GRPCScheme, cmd.DefaultAcraTranslatorGRPCHost, cmd.DefaultAcraTranslatorGRPCPort, "")
		log.Infof("No incoming connection string is set: by default gRPC connections are being listen %v", *incomingConnectionGRPCString)
	}

	// now it's stub as default values
	config.SetDetectPoisonRecords(*detectPoisonRecords)
	config.SetStopOnPoison(*stopOnPoison)
	config.SetScriptOnPoison(*scriptOnPoison)
	config.SetKeysDir(*keysDir)
	config.SetIncomingConnectionHTTPString(*incomingConnectionHTTPString)
	config.SetIncomingConnectionGRPCString(*incomingConnectionGRPCString)
	config.SetConfigPath(DefaultConfigPath)
	config.SetDebug(*debug)
	config.SetTraceToLog(cmd.IsTraceToLogOn())
	config.SetUseClientIDFromConnection(*useClientIDFromConnection)

	cmd.SetupTracing(ServiceName)

	keyLoader, err := keyloader.GetInitializedMasterKeyLoader(hashicorp.GetVaultCLIParameters())
	if err != nil {
		log.WithError(err).Errorln("Can't initialize ACRA_MASTER_KEY loader")
		return err
	}

	log.Infof("Initialising keystore...")
	var keyStore keystore.ServerKeyStore
	var transportKeystore keystore.TranslationKeyStore
	if filesystem2.IsKeyDirectory(*keysDir) {
		keyStore, transportKeystore, err = openKeyStoreV2(*keysDir, *keysCacheSize, keyLoader)
	} else {
		keyStore, transportKeystore, err = openKeyStoreV1(*keysDir, *keysCacheSize, keyLoader)
	}
	if err != nil {
		log.WithError(err).Errorln("Can't open keyStore")
		return err
	}

	if *cacheKeystoreOnStart {
		if *keysCacheSize == keystore.WithoutCache {
			log.Errorln("Can't cache on start with disabled cache")
			os.Exit(1)
		}
		if err := keyStore.CacheOnStart(); err != nil {
			log.WithError(err).Errorln("Failed to cache keystore on start")
			return err
		}

		if err := transportKeystore.CacheOnStart(); err != nil {
			log.WithError(err).Errorln("Failed to cache transport keystore on start")
			return err
		}
		log.Info("Cached keystore on start successfully")
	}

	log.Infof("Keystore init OK")
	if err := crypto.InitRegistry(keyStore); err != nil {
		log.WithError(err).Errorln("Can't initialize crypto registry")
		return err
	}

	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	var auditLogHandler *logging.AuditLogHandler
	if *enableAuditLog {
		/*
			Audit log feature relies on Go's defer functions mechanism for the correct finalization. For this reason,
			developers shouldn't use logging messages inside defer functions. Otherwise, those messages may be lost
		*/
		auditLogKey, err := keyStore.GetLogSecretKey()
		if err != nil {
			log.WithError(err).Errorln("Can't fetch log key from keystore")
			return err
		}
		hooks, err := logging.NewHooks(auditLogKey, *loggingFormat)
		if err != nil {
			log.WithError(err).Errorln("Can't create hooks")
			return err
		}
		// zeroing key after initializing crypto-hook
		utils.ZeroizeSymmetricKey(auditLogKey)
		formatter.SetHooks(hooks)

		auditLogHandler, err = logging.NewAuditLogHandler(formatter, writer)
		if err != nil {
			log.WithError(err).Errorln("Can't create handler")
			return err
		}
		// Set updated formatter for audit log
		log.SetFormatter(auditLogHandler)
		defer auditLogHandler.FinalizeChain()
	}

	httpWrapper, err := network.NewHTTPServerConnectionWrapper()
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).Errorln("Can't initialize HTTPServerConnectionWrapper")
		os.Exit(1)
	}
	httpWrapper.AddConnectionContextCallback(common.ConnectionToContextCallback{})
	config.HTTPConnectionWrapper = httpWrapper
	// we should register transport callback last because http2 server require that it should receive *tls.Conn object
	// and we need to wrap source connection with our wrappers before switching to TLS
	var httpTransportCallback network.ConnectionCallback
	// --------- Config  -----------
	log.Infof("Configuring transport...")

	log.WithField("client_id_from_connection", *useClientIDFromConnection).Infoln("Selecting transport: use TLS transport wrapper")
	tlsConfig, err := network.NewTLSConfigFromBaseArgs()
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
			Errorln("Configuration error: can't create TLS config")
		os.Exit(1)
	}
	var clientIDExtractor network.TLSClientIDExtractor

	idConverter, err := network.NewDefaultHexIdentifierConverter()
	if err != nil {
		log.WithError(err).Errorln("Can't initialize identifier converter")
		os.Exit(1)
	}
	identifierExtractor, err := network.NewIdentifierExtractorByType(*tlsIdentifierExtractorType)
	if err != nil {
		log.WithField("type", *tlsIdentifierExtractorType).WithError(err).Errorln("Can't initialize identifier extractor")
		os.Exit(1)
	}
	clientIDExtractor, err = network.NewTLSClientIDExtractor(identifierExtractor, idConverter)
	if err != nil {
		log.WithError(err).Errorln("Can't initialize clientID extractor")
		os.Exit(1)
	}
	config.SetTLSClientIDExtractor(clientIDExtractor)

	// client's config nil because we don't need to establish tls connection with database or any third side
	tlsWrapper, err := network.NewTLSAuthenticationConnectionWrapper(*useClientIDFromConnection, nil, tlsConfig, clientIDExtractor)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).Errorln("Can't initialize TLS connection wrapper")
		os.Exit(1)
	}
	httpTransportCallback = tlsWrapper
	config.GRPCConnectionWrapper = tlsWrapper
	config.SetTLSConfig(tlsConfig)

	safeCloseConnectionCallback := network.SafeCloseConnectionCallback{}
	httpWrapper.AddCallback(safeCloseConnectionCallback)
	config.GRPCConnectionWrapper.AddOnServerHandshakeCallback(safeCloseConnectionCallback)

	encryptor, err := storage.NewSCellEncryptor(keyStore)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).Errorln("Can't initialize token encryptor")
		return err
	}
	var tokenStorage common2.TokenStorage
	redis := cmd.GetRedisParameters()
	if *boltTokenbDB != "" {
		log.Infoln("Initialize bolt db storage for tokens")
		db, err := bolt.Open(*boltTokenbDB, 0600, nil)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize boltdb token storage")
			return err
		}
		defer db.Close()
		tokenStorage = storage.NewBoltDBTokenStorage(db)
		log.Infoln("Initialized bolt db storage for tokens")
	} else if redis.TokensConfigured() {
		log.Infoln("Initialize redis db storage for tokens")
		redisClient, err := storage.NewRedisClient(redis.HostPort, redis.Password, redis.DBTokens, nil)
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
	tokenStorage = storage.WrapStorageWithEncryption(tokenStorage, encryptor)

	tokenizer, err := pseudonymization.NewPseudoanonymizer(tokenStorage)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).Errorln("Can't initialize tokenizer")
		return err
	}
	config.SetTokenizer(tokenizer)
	poisonCallbacks := poison.NewCallbackStorage()
	if config.DetectPoisonRecords() {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodePoisonRecordDetectionMessage).Infoln("Turned on poison record detection")
		// used to turn off poison record detection which rely on HasCallbacks
		poisonCallbacks.AddCallback(poison.EmptyCallback{})
		if config.ScriptOnPoison() != "" {
			poisonCallbacks.AddCallback(poison.NewExecuteScriptCallback(config.ScriptOnPoison()))
			log.WithField("poison_run_script_file", *scriptOnPoison).Infoln("Turned on script execution for on detected poison record")
		}
		// should setup "stopOnPoison" as last poison record callback"
		if config.StopOnPoison() {
			poisonCallbacks.AddCallback(&poison.StopCallback{})
			log.Infoln("Turned on poison record callback that stops acra-server after poison record detection")
		}
	}
	translatorData := &common.TranslatorData{
		Tokenizer:             tokenizer,
		Config:                config,
		Keystorage:            transportKeystore,
		PoisonRecordCallbacks: poisonCallbacks,
		UseConnectionClientID: config.GetUseClientIDFromConnection(),
		TLSClientIDExtractor:  config.GetTLSClientIDExtractor(),
	}
	grpcServer, err := grpc_api.NewServer(translatorData, config.GRPCConnectionWrapper)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).Errorln("Can't initialize gRPC service factory")
		return err
	}

	waitTimeout := time.Duration(*closeConnectionTimeout) * time.Second
	readerServer, err := server.NewReaderServer(translatorData, grpcServer, waitTimeout)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartService).
			Errorf("System error: can't start %s", ServiceName)
		return err
	}

	mainContext, cancel := context.WithCancel(context.Background())
	mainContext = logging.SetLoggerToContext(mainContext, log.NewEntry(log.StandardLogger()))

	log.Debugf("Registering process signal handlers")
	sigHandlerSIGTERM, err := cmd.NewSignalHandler([]os.Signal{os.Interrupt, syscall.SIGTERM})
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantRegisterSignalHandler).
			Errorln("System error: can't register SIGTERM handler")
		return err
	}
	sigHandlerSIGHUP, err := cmd.NewSignalHandler([]os.Signal{syscall.SIGHUP})
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantRegisterSignalHandler).
			Errorln("System error: can't register SIGHUP handler")
		return err
	}

	// this waitGroup object is used for synchronizing of background goroutines (system signals handlers) that spawned in this function
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

	if *prometheusAddress != "" {
		common.RegisterMetrics(ServiceName)
		_, prometheusHTTPServer, err := cmd.RunPrometheusHTTPHandler(*prometheusAddress)
		if err != nil {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorPrometheusHTTPHandler).WithError(err).WithField("incoming_connection_prometheus_metrics_string", *prometheusAddress).Errorln("Can't run prometheus handler")
			return err
		}
		log.Infof("Configured to send metrics and stats to `incoming_connection_prometheus_metrics_string`")
		prometheusClose := func() {
			log.Infoln("Stop prometheus HTTP exporter")
			if err := prometheusHTTPServer.Close(); err != nil {
				log.WithError(err).Errorln("Error on prometheus server close")
			}
		}
		sigHandlerSIGTERM.AddCallback(prometheusClose)
		sigHandlerSIGHUP.AddCallback(prometheusClose)
		config.HTTPConnectionWrapper.AddCallback(common.NewMetricConnectionCallback(common.HTTPConnectionType))
		config.GRPCConnectionWrapper.AddOnServerHandshakeCallback(common.NewMetricConnectionCallback(common.GRPCConnectionType))
	}

	if *enableAuditLog {
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
						readerServer.Stop()
						cancel()
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

	sigHandlerSIGTERM.AddCallback(func() {
		log.Infof("Received incoming SIGTERM or SIGINT signal")
		readerServer.Stop()
		// send global stop for all background goroutines of readerServer
		cancel()
		log.Infof("Server graceful shutdown completed, bye PID: %v", os.Getpid())
	})

	// we initialize pipeWrite only in SIGHUP handler
	var pipeWrite *os.File
	sigHandlerSIGHUP.AddCallback(func() {
		shutdownCurrentInstance := func(err error) {
			readerServer.Stop()
			cancel()
		}

		log.Infof("Received incoming SIGHUP signal")
		log.Debugf("Stop accepting new connections, waiting until current connections close")
		readerServer.StopListeners()

		// Set env flag for forked process
		if err := os.Setenv(GracefulRestartEnv, "true"); err != nil {
			log.WithError(err).Errorf("Unexpected error on os.Setenv, graceful restart won't work. Please check env variables, especially %s", GracefulRestartEnv)
			shutdownCurrentInstance(err)
			return
		}

		var fdHTTP, fdGRPC uintptr
		if listener := readerServer.GetHTTPListener(); listener != nil {
			fdHTTP, err = network.ListenerFileDescriptor(listener)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetFileDescriptor).
					Errorln("System error: failed to get Acra HTTP file descriptor:", err)
				shutdownCurrentInstance(err)
				return
			}
		}
		if listener := readerServer.GetGRPCListener(); listener != nil {
			fdGRPC, err = network.ListenerFileDescriptor(listener)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetFileDescriptor).
					Errorln("System error: failed to get Acra gRPC file descriptor:", err)
				shutdownCurrentInstance(err)
				return
			}
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
			Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd(), fdHTTP, fdGRPC, pipeRead.Fd()},
		}
		log.Debugf("Forking new process of %s", ServiceName)

		// Fork new process
		fork, err := syscall.ForkExec(os.Args[0], os.Args, execSpec)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantForkProcess).
				Errorln("System error: failed to fork new process", err)
			shutdownCurrentInstance(err)
			return
		}

		log.Infof("%s process forked to PID: %v", ServiceName, fork)

		// Wait a maximum of N seconds for existing connections to finish
		if utils.WaitWithTimeout(readerServer.GetConnectionManager().WaitGroup, time.Duration(*closeConnectionTimeout)*time.Second) {
			log.Warningf("Server shutdown Timeout: %d active connections will be cut", readerServer.GetConnectionManager().Counter)
		}
		log.Infof("Server graceful restart completed, bye PID: %v", os.Getpid())
		shutdownCurrentInstance(nil)
	})

	// -------- START -----------

	log.Infof("Setup ready. Start listening to connections. Current PID: %v", os.Getpid())

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
	httpWrapper.AddCallback(httpTransportCallback)
	if os.Getenv(GracefulRestartEnv) == "true" {
		readerServer.StartFromFileDescriptor(mainContext, DescriptorHTTP, DescriptorGRPC)
	} else {
		readerServer.Start(mainContext)
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

func openKeyStoreV1(keysDir string, cacheSize int, loader keyloader.MasterKeyLoader) (keystore.ServerKeyStore, keystore.TranslationKeyStore, error) {
	masterKey, err := loader.LoadMasterKey()
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantLoadMasterKey).
			Errorln("Cannot load master key")
		return nil, nil, err
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitPrivateKeysEncryptor).WithError(err).Errorln("Can't init scell encryptor")
		return nil, nil, err
	}
	var keyStorage filesystem.Storage = &filesystem.DummyStorage{}
	redis := cmd.GetRedisParameters()
	if redis.KeysConfigured() {
		keyStorage, err = filesystem.NewRedisStorage(redis.HostPort, redis.Password, redis.DBKeys, nil)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize Redis client")
			return nil, nil, err
		}
	}
	keyStore := filesystem.NewCustomFilesystemKeyStore()
	keyStore.KeyDirectory(keysDir)
	keyStore.CacheSize(cacheSize)
	keyStore.Encryptor(scellEncryptor)
	keyStore.Storage(keyStorage)
	keyStoreV1, err := keyStore.Build()
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
			Errorln("Can't initialize keystore")
		return nil, nil, err
	}

	transportKeyStore := filesystem.NewCustomTranslatorFileSystemKeyStore()
	transportKeyStore.KeyDirectory(keysDir)
	transportKeyStore.Encryptor(scellEncryptor)
	transportKeyStore.Storage(keyStorage)
	transportKeyStoreV1, err := transportKeyStore.Build()
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
			Errorln("Can't initialize transport keystore")
		return nil, nil, err
	}

	return keyStoreV1, transportKeyStoreV1, nil
}

func openKeyStoreV2(keysDir string, cacheSize int, loader keyloader.MasterKeyLoader) (keystore.ServerKeyStore, keystore.TranslationKeyStore, error) {
	if cacheSize != keystore.WithoutCache {
		return nil, nil, keystore.ErrCacheIsNotSupportedV2
	}

	encryption, signature, err := loader.LoadMasterKeys()
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantLoadMasterKey).
			Errorln("Cannot load master key")
		return nil, nil, err
	}
	suite, err := keystoreV2.NewSCellSuite(encryption, signature)
	if err != nil {
		log.WithError(err).Error("Failed to initialize Secure Cell crypto suite")
		return nil, nil, err
	}
	var backend filesystemBackendV2CE.Backend
	redis := cmd.GetRedisParameters()
	if redis.KeysConfigured() {
		config := &filesystemBackendV2CE.RedisConfig{
			RootDir: keysDir,
			Options: redis.KeysOptions(),
		}
		backend, err = filesystemBackendV2CE.OpenRedisBackend(config)
		if err != nil {
			log.WithError(err).Error("Cannot connect to Redis keystore")
			return nil, nil, err
		}
	} else {
		backend, err = filesystemBackendV2CE.OpenDirectoryBackend(keysDir)
		if err != nil {
			log.WithError(err).Error("Cannot open key directory")
			return nil, nil, err
		}
	}
	keyDirectory, err := filesystem2.CustomKeyStore(backend, suite)
	if err != nil {
		log.WithError(err).Error("Failed to initialize key directory")
		return nil, nil, err
	}
	keystore := keystoreV2.NewServerKeyStore(keyDirectory)
	transportKeystoreV2 := keystoreV2.NewTranslatorKeyStore(keyDirectory)
	return keystore, transportKeystoreV2, nil
}
