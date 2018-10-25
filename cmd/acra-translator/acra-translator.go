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
	"go.opencensus.io/exporter/jaeger"
	"go.opencensus.io/trace"
	_ "net/http/pprof"
	"os"
	"syscall"
	"time"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

// Constants handy for AcraTranslator.
const (
	ServiceName          = "acra-translator"
	DEFAULT_WAIT_TIMEOUT = 10
)

// DEFAULT_CONFIG_PATH relative path to config which will be parsed as default
var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName(ServiceName)

func main() {
	config := NewConfig()
	loggingFormat := flag.String("logging_format", "plaintext", "Logging format: plaintext, json or CEF")
	log.Infof("Starting service %v [pid=%v]", ServiceName, os.Getpid())

	incomingConnectionHTTPString := flag.String("incoming_connection_http_string", "", "Connection string for HTTP transport like http://0.0.0.0:9595")
	incomingConnectionGRPCString := flag.String("incoming_connection_grpc_string", "", "Default option: connection string for gRPC transport like grpc://0.0.0.0:9696")

	keysDir := flag.String("keys_dir", keystore.DefaultKeyDirShort, "Folder from which will be loaded keys")
	keysCacheSize := flag.Int("keystore_cache_size", keystore.InfiniteCacheSize, "Count of keys that will be stored in in-memory LRU cache in encrypted form. 0 - no limits, -1 - turn off cache")

	secureSessionID := flag.String("securesession_id", "acra_translator", "Id that will be sent in secure session")

	detectPoisonRecords := flag.Bool("poison_detect_enable", true, "Turn on poison record detection, if server shutdown is disabled, AcraTranslator logs the poison record detection and returns error")
	stopOnPoison := flag.Bool("poison_shutdown_enable", false, "On detecting poison record: log about poison record detection, stop and shutdown")
	scriptOnPoison := flag.String("poison_run_script_file", "", "On detecting poison record: log about poison record detection, execute script, return decrypted data")

	closeConnectionTimeout := flag.Int("incoming_connection_close_timeout", DEFAULT_WAIT_TIMEOUT, "Time that AcraTranslator will wait (in seconds) on stop signal before closing all connections")

	prometheusAddress := flag.String("incoming_connection_prometheus_metrics_string", "", "URL which will be used to expose Prometheus metrics (use <URL>/metrics address to pull metrics)")

	tracing := flag.Bool("tracing_enable", false, "Enable tracing")
	traceToLog := flag.Bool("tracing_log_enable", false, "Export trace data to log")
	traceToJaeger := flag.Bool("tracing_jaeger_enable", false, "Export trace data to jaeger")
	jaegerAgentEndpoint := flag.String("jaeger_agent_endpoint", "127.0.0.1:6831", "Jaeger agent endpoint that will be used to export trace data")
	jaegerEndpoint := flag.String("jaeger_endpoint", "http://localhost:14268", "Jaeger endpoint that will be used to export trace data")

	verbose := flag.Bool("v", false, "Log to stderr all INFO, WARNING and ERROR logs")
	debug := flag.Bool("d", false, "Log everything to stderr")

	err := cmd.Parse(DEFAULT_CONFIG_PATH, ServiceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}

	logging.CustomizeLogging(*loggingFormat, ServiceName)

	log.Infof("Validating service configuration...")
	cmd.ValidateClientID(*secureSessionID)

	if len(*incomingConnectionHTTPString) == 0 && len(*incomingConnectionGRPCString) == 0 {
		*incomingConnectionGRPCString = network.BuildConnectionString(network.GRPC_SCHEME, cmd.DEFAULT_ACRATRANSLATOR_GRPC_HOST, cmd.DEFAULT_ACRATRANSLATOR_GRPC_PORT, "")
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
	config.SetConfigPath(DEFAULT_CONFIG_PATH)
	config.SetDebug(*debug)
	config.SetTraceToLog(*traceToLog)
	config.SetTracing(*tracing)

	if *tracing {
		if *traceToLog {
			trace.RegisterExporter(&logging.LogSpanExporter{})
		}

		if *traceToJaeger {
			jaegerEndpoint, err := jaeger.NewExporter(jaeger.Options{
				AgentEndpoint: *jaegerAgentEndpoint,
				Endpoint:      *jaegerEndpoint,
				ServiceName:   ServiceName,
			})
			if err != nil {
				log.Fatalf("Failed to create the Jaeger exporter: %v", err)
				os.Exit(1)
			}
			// And now finally register it as a Trace Exporter
			trace.RegisterExporter(jaegerEndpoint)
		}
	}

	log.Infof("Initialising keystore...")
	masterKey, err := keystore.GetMasterKeyFromEnvironment()
	if err != nil {
		log.WithError(err).Errorln("Can't load master key")
		os.Exit(1)
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithError(err).Errorln("Can't init scell encryptor")
		os.Exit(1)
	}
	keyStore, err := filesystem.NewTranslatorFileSystemKeyStore(*keysDir, scellEncryptor, *keysCacheSize)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
			Errorln("Can't initialise keystore")
		os.Exit(1)
	}
	log.Infof("Keystore init OK")

	// --------- Config  -----------
	log.Infof("Configuring transport...")
	log.Infof("Selecting transport: use Secure Session transport wrapper")
	config.ConnectionWrapper, err = network.NewSecureSessionConnectionWrapper(keyStore)
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

	var readerServer *ReaderServer
	waitTimeout := time.Duration(*closeConnectionTimeout) * time.Second
	readerServer, err = NewReaderServer(config, keyStore, waitTimeout)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartService).
			Errorf("System error: can't start %s", ServiceName)
		panic(err)
	}

	mainContext, cancel := context.WithCancel(context.Background())
	mainContext = logging.SetLoggerToContext(mainContext, log.NewEntry(log.StandardLogger()))

	go sigHandlerSIGTERM.Register()
	sigHandlerSIGTERM.AddCallback(func() {
		log.Infof("Received incoming SIGTERM or SIGINT signal")
		readerServer.Stop()
		// send global stop
		cancel()

		log.Infof("Server graceful shutdown completed, bye PID: %v", os.Getpid())
		os.Exit(0)
	})

	if *prometheusAddress != "" {
		registerMetrics()
		_, prometheusHTTPServer, err := cmd.RunPrometheusHTTPHandler(*prometheusAddress)
		if err != nil {
			log.WithError(err).WithField("incoming_connection_prometheus_metrics_string", *prometheusAddress).Errorln("Can't run prometheus handler")
			os.Exit(1)
		}
		log.Infof("Configured to send metrics and stats to `incoming_connection_prometheus_metrics_string`")
		sigHandlerSIGTERM.AddCallback(func() {
			log.Infoln("Stop prometheus http exporter")
			prometheusHTTPServer.Close()
		})
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

	readerServer.Start(mainContext)
}
