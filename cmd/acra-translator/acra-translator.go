/*
Copyright 2018, Cossack Labs Limited

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
	"context"
	"flag"
	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	"github.com/cossacklabs/acra/cmd/acra-translator/grpc_api"
	"github.com/cossacklabs/acra/cmd/acra-translator/server"
	_ "net/http/pprof"
	"os"
	"syscall"
	"time"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

// Constants handy for AcraTranslator.
const (
	ServiceName        = "acra-translator"
	defaultWaitTimeout = 10
	GracefulRestartEnv = "GRACEFUL_RESTART"
	// We use this values as a file descriptors pointers on SIGHUP signal processing.
	// We definitely know (because we implement this), that new forked process starts
	// with three descriptors in mind - stdin (0), stdout (1), stderr(2). And then we
	// use HTTP (3) and gRPC (4) descriptors. Take a look at callback function that is
	// called on SIGHUP event for more details
	DescriptorHTTP = 3
	DescriptorGRPC = 4
)

// DefaultConfigPath relative path to config which will be parsed as default
var DefaultConfigPath = utils.GetConfigPathByName(ServiceName)

func main() {
	config := common.NewConfig()
	loggingFormat := flag.String("logging_format", "plaintext", "Logging format: plaintext, json or CEF")
	log.WithField("version", utils.VERSION).Infof("Starting service %v [pid=%v]", ServiceName, os.Getpid())

	incomingConnectionHTTPString := flag.String("incoming_connection_http_string", "", "Connection string for HTTP transport like http://0.0.0.0:9595")
	incomingConnectionGRPCString := flag.String("incoming_connection_grpc_string", "", "Default option: connection string for gRPC transport like grpc://0.0.0.0:9696")

	keysDir := flag.String("keys_dir", keystore.DefaultKeyDirShort, "Folder from which will be loaded keys")
	keysCacheSize := flag.Int("keystore_cache_size", keystore.InfiniteCacheSize, "Count of keys that will be stored in in-memory LRU cache in encrypted form. 0 - no limits, -1 - turn off cache")

	secureSessionID := flag.String("securesession_id", "acra_translator", "Id that will be sent in secure session")

	detectPoisonRecords := flag.Bool("poison_detect_enable", true, "Turn on poison record detection, if server shutdown is disabled, AcraTranslator logs the poison record detection and returns error")
	stopOnPoison := flag.Bool("poison_shutdown_enable", false, "On detecting poison record: log about poison record detection, stop and shutdown")
	scriptOnPoison := flag.String("poison_run_script_file", "", "On detecting poison record: log about poison record detection, execute script, return decrypted data")

	closeConnectionTimeout := flag.Int("incoming_connection_close_timeout", defaultWaitTimeout, "Time that AcraTranslator will wait (in seconds) on stop signal before closing all connections")

	prometheusAddress := flag.String("incoming_connection_prometheus_metrics_string", "", "URL which will be used to expose Prometheus metrics (use <URL>/metrics address to pull metrics)")

	cmd.RegisterTracingCmdParameters()
	cmd.RegisterJaegerCmdParameters()

	verbose := flag.Bool("v", false, "Log to stderr all INFO, WARNING and ERROR logs")
	debug := flag.Bool("d", false, "Log everything to stderr")

	err := cmd.Parse(DefaultConfigPath, ServiceName)
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
	log.Infof("Validating service configuration...")
	cmd.ValidateClientID(*secureSessionID)

	if len(*incomingConnectionHTTPString) == 0 && len(*incomingConnectionGRPCString) == 0 {
		*incomingConnectionGRPCString = network.BuildConnectionString(network.GRPCScheme, cmd.DefaultAcraTranslatorGRPCHost, cmd.DefaultAcraTranslatorGRPCPort, "")
		log.Infof("No incoming connection string is set: by default gRPC connections are being listen %v", *incomingConnectionGRPCString)
	}

	// now it's stub as default values
	config.SetDetectPoisonRecords(*detectPoisonRecords)
	config.SetStopOnPoison(*stopOnPoison)
	config.SetScriptOnPoison(*scriptOnPoison)
	config.SetKeysDir(*keysDir)
	config.SetServerID([]byte(*secureSessionID))
	config.SetIncomingConnectionHTTPString(*incomingConnectionHTTPString)
	config.SetIncomingConnectionGRPCString(*incomingConnectionGRPCString)
	config.SetConfigPath(DefaultConfigPath)
	config.SetDebug(*debug)
	config.SetTraceToLog(cmd.IsTraceToLogOn())

	cmd.SetupTracing(ServiceName)

	log.Infof("Initialising keystore...")
	var keyStore keystore.TranslationKeyStore
	if filesystemV2.IsKeyDirectory(*keysDir) {
		keyStore = openKeyStoreV2(*keysDir)
	} else {
		keyStore = openKeyStoreV1(*keysDir, *keysCacheSize)
	}
	log.Infof("Keystore init OK")

	// --------- Config  -----------
	log.Infof("Configuring transport...")
	log.Infof("Selecting transport: use Secure Session transport wrapper")
	config.ConnectionWrapper, err = network.NewSecureSessionConnectionWrapper([]byte(*secureSessionID), keyStore)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
			Errorln("Configuration error: can't initialize secure session connection wrapper")
		os.Exit(1)
	}

	log.Debugf("Registering process signal handlers")
	sigHandlerSIGTERM, err := cmd.NewSignalHandler([]os.Signal{os.Interrupt, syscall.SIGTERM})
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantRegisterSignalHandler).
			Errorln("System error: can't register SIGTERM handler")
		os.Exit(1)
	}
	sigHandlerSIGHUP, err := cmd.NewSignalHandler([]os.Signal{syscall.SIGHUP})
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantRegisterSignalHandler).
			Errorln("System error: can't register SIGHUP handler")
		os.Exit(1)
	}

	var readerServer *server.ReaderServer
	waitTimeout := time.Duration(*closeConnectionTimeout) * time.Second
	readerServer, err = server.NewReaderServer(config, keyStore, &grpc_api.GRPCServerFactory{}, waitTimeout)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartService).
			Errorf("System error: can't start %s", ServiceName)
		panic(err)
	}

	mainContext, cancel := context.WithCancel(context.Background())
	mainContext = logging.SetLoggerToContext(mainContext, log.NewEntry(log.StandardLogger()))

	go sigHandlerSIGTERM.RegisterWithContext(mainContext)
	sigHandlerSIGTERM.AddCallback(func() {
		log.Infof("Received incoming SIGTERM or SIGINT signal")
		readerServer.Stop()
		// send global stop
		cancel()

		log.Infof("Server graceful shutdown completed, bye PID: %v", os.Getpid())
		os.Exit(0)
	})

	go sigHandlerSIGHUP.RegisterWithContext(mainContext)
	sigHandlerSIGHUP.AddCallback(func() {
		log.Infof("Received incoming SIGHUP signal")
		log.Debugf("Stop accepting new connections, waiting until current connections close")
		readerServer.StopListeners()

		// Set env flag for forked process
		if err := os.Setenv(GracefulRestartEnv, "true"); err != nil {
			log.WithError(err).Fatalf("Unexpected error on os.Setenv, graceful restart won't work. Please check env variables, especially %s", GracefulRestartEnv)
		}

		var fdHTTP, fdGRPC uintptr
		if listener := readerServer.GetHTTPListener(); listener != nil {
			fdHTTP, err = network.ListenerFileDescriptor(listener)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetFileDescriptor).
					Fatalln("System error: failed to get Acra HTTP file descriptor:", err)

			}
		}
		if listener := readerServer.GetGRPCListener(); listener != nil {
			fdGRPC, err = network.ListenerFileDescriptor(listener)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetFileDescriptor).
					Fatalln("System error: failed to get Acra gRPC file descriptor:", err)

			}
		}
		execSpec := &syscall.ProcAttr{
			Env:   os.Environ(),
			Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd(), fdHTTP, fdGRPC},
		}
		log.Debugf("Forking new process of %s", ServiceName)

		// Fork new process
		fork, err := syscall.ForkExec(os.Args[0], os.Args, execSpec)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantForkProcess).
				Fatalln("System error: failed to fork new process", err)
		}

		log.Infof("%s process forked to PID: %v", ServiceName, fork)

		// Wait a maximum of N seconds for existing connections to finish
		if utils.WaitWithTimeout(readerServer.GetConnectionManager().WaitGroup, time.Duration(*closeConnectionTimeout)*time.Second) {
			log.Warningf("Server shutdown timeout: %d active connections will be cut", readerServer.GetConnectionManager().Counter)
		}
		log.Infof("Server graceful restart completed, bye PID: %v", os.Getpid())
		os.Exit(0)
	})

	if *prometheusAddress != "" {
		common.RegisterMetrics(ServiceName)
		_, prometheusHTTPServer, err := cmd.RunPrometheusHTTPHandler(*prometheusAddress)
		if err != nil {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorPrometheusHTTPHandler).WithError(err).WithField("incoming_connection_prometheus_metrics_string", *prometheusAddress).Errorln("Can't run prometheus handler")
			os.Exit(1)
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
	}

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

	if os.Getenv(GracefulRestartEnv) == "true" {
		readerServer.StartFromFileDescriptor(mainContext, DescriptorHTTP, DescriptorGRPC)
	} else {
		readerServer.Start(mainContext)
	}
}

func openKeyStoreV1(keysDir string, cacheSize int) keystore.TranslationKeyStore {
	masterKey, err := keystore.GetMasterKeyFromEnvironment()
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantLoadMasterKey).
			Errorln("Cannot load master key")
		os.Exit(1)
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitPrivateKeysEncryptor).
			Errorln("Can't init scell encryptor")
		os.Exit(1)
	}
	keyStore, err := filesystem.NewTranslatorFileSystemKeyStore(keysDir, scellEncryptor, cacheSize)
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
			Errorln("Can't initialise keystore")
		os.Exit(1)
	}
	return keyStore
}

func openKeyStoreV2(keyDirPath string) keystore.TranslationKeyStore {
	encryption, signature, err := keystoreV2.GetMasterKeysFromEnvironment()
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantLoadMasterKey).
			Errorln("Cannot load master key")
		os.Exit(1)
	}
	suite, err := keystoreV2.NewSCellSuite(encryption, signature)
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitPrivateKeysEncryptor).
			Error("failed to initialize Secure Cell crypto suite")
		os.Exit(1)
	}
	keyDir, err := filesystemV2.OpenDirectoryRW(keyDirPath, suite)
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
			WithField("path", keyDirPath).Error("cannot open key directory")
		os.Exit(1)
	}
	return keystoreV2.NewTranslatorKeyStore(keyDir)
}
