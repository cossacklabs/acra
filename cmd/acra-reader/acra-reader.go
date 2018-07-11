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
	"context"
	"flag"
	_ "net/http/pprof"
	"os"
	"syscall"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

const (
	SERVICE_NAME = "acra-reader"
)

// DEFAULT_CONFIG_PATH relative path to config which will be parsed as default
var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName(SERVICE_NAME)

func main() {
	config := NewConfig()
	loggingFormat := flag.String("logging_format", "plaintext", "Logging format: plaintext, json or CEF")
	logging.CustomizeLogging(*loggingFormat, SERVICE_NAME)
	log.Infof("Starting service %v", SERVICE_NAME)

	incomingConnectionHTTPString := flag.String("incoming_connection_http_string", network.BuildConnectionString(cmd.DEFAULT_ACRA_CONNECTION_PROTOCOL, cmd.DEFAULT_ACRAREADER_HTTP_HOST, cmd.DEFAULT_ACRAREADER_HTTP_PORT, ""), "Connection string for HTTP transport like http://x.x.x.x:yyyy")
	incomingConnectionGRPCString := flag.String("incoming_connection_grpc_string", network.BuildConnectionString(cmd.DEFAULT_ACRA_CONNECTION_PROTOCOL, cmd.DEFAULT_ACRAREADER_GRPC_HOST, cmd.DEFAULT_ACRAREADER_GRPC_PORT, ""), "Connection string for gRPC transport like grpc://x.x.x.x:yyyy")

	keysDir := flag.String("keys_dir", keystore.DEFAULT_KEY_DIR_SHORT, "Folder from which will be loaded keys")

	secureSessionId := flag.String("securesession_id", "acra_reader", "Id that will be sent in secure session")

	stopOnPoison := flag.Bool("poison_shutdown_enable", false, "Stop on detecting poison record")
	scriptOnPoison := flag.String("poison_run_script_file", "", "Execute script on detecting poison record")

	verbose := flag.Bool("v", false, "Log to stderr")
	debug := flag.Bool("d", false, "Turn on debug logging")

	err := cmd.Parse(DEFAULT_CONFIG_PATH, SERVICE_NAME)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}

	// if log format was overridden
	logging.CustomizeLogging(*loggingFormat, SERVICE_NAME)

	log.Infof("Validating service configuration")
	cmd.ValidateClientId(*secureSessionId)

	if *debug {
		logging.SetLogLevel(logging.LOG_DEBUG)
	} else if *verbose {
		logging.SetLogLevel(logging.LOG_VERBOSE)
	} else {
		logging.SetLogLevel(logging.LOG_DISCARD)
	}

	// now it's stub as default values
	config.SetStopOnPoison(*stopOnPoison)
	config.SetScriptOnPoison(*scriptOnPoison)
	config.SetKeysDir(*keysDir)
	config.SetServerId([]byte(*secureSessionId))
	config.SetIncomingConnectionHTTPString(*incomingConnectionHTTPString)
	config.SetIncomingConnectionGRPCString(*incomingConnectionGRPCString)
	config.SetConfigPath(DEFAULT_CONFIG_PATH)
	config.SetDebug(*debug)

	log.Infof("Initialising keystore")
	masterKey, err := keystore.GetMasterKeyFromEnvironment()
	if err != nil {
		log.WithError(err).Errorln("can't load master key")
		os.Exit(1)
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithError(err).Errorln("can't init scell encryptor")
		os.Exit(1)
	}
	keyStore, err := keystore.NewFilesystemKeyStore(*keysDir, scellEncryptor)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
			Errorln("Can't initialise keystore")
		os.Exit(1)
	}

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
	readerServer, err = NewReaderServer(config, keyStore)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartService).
			Errorln("System error: can't start %s", SERVICE_NAME)
		panic(err)
	}

	mainContext, cancel := context.WithCancel(context.Background())
	mainContext = logging.SetLoggerToContext(mainContext, log.NewEntry(log.StandardLogger()))

	go sigHandlerSIGTERM.Register()
	sigHandlerSIGTERM.AddCallback(func() {
		log.Infof("Received incoming SIGTERM or SIGINT signal")
		// Stop accepting new connections
		cancel()

		log.Infof("Server graceful shutdown completed, bye PID: %v", os.Getpid())
		os.Exit(0)
	})

	log.Infof("Start listening to connections. Current PID: %v", os.Getpid())
	readerServer.Start(mainContext)
}
