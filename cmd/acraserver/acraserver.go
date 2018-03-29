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
	"errors"
	"flag"
	"net/http"
	_ "net/http/pprof"
	"os"
	"syscall"
	"time"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/firewall"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

// DEFAULT_CONFIG_PATH relative path to config which will be parsed as default
var restartSignalsChannel chan os.Signal
var errorSignalChannel chan os.Signal

const (
	DEFAULT_ACRASERVER_WAIT_TIMEOUT = 10
	GRACEFUL_ENV                    = "GRACEFUL_RESTART"
	DESCRIPTOR_ACRA                 = 3
	DESCRIPTOR_API                  = 4
)

var SERVICE_NAME = "acraserver"
var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName(SERVICE_NAME)
var ErrWaitTimeout = errors.New("timeout")

func main() {
	config := NewConfig()

	dbHost := flag.String("db_host", "", "Host to db")
	dbPort := flag.Int("db_port", 5432, "Port to db")

	host := flag.String("host", cmd.DEFAULT_ACRA_HOST, "Host for AcraServer")
	port := flag.Int("port", cmd.DEFAULT_ACRA_PORT, "Port for AcraServer")
	commandsPort := flag.Int("commands_port", cmd.DEFAULT_ACRA_API_PORT, "Port for AcraServer for http api")

	keysDir := flag.String("keys_dir", keystore.DEFAULT_KEY_DIR_SHORT, "Folder from which will be loaded keys")

	hexFormat := flag.Bool("hex_bytea", false, "Hex format for Postgresql bytea data (default)")
	escapeFormat := flag.Bool("escape_bytea", false, "Escape format for Postgresql bytea data")

	serverId := flag.String("server_id", "acra_server", "Id that will be sent in secure session")

	verbose := flag.Bool("v", false, "Log to stdout")
	flag.Bool("wholecell", true, "Acrastruct will stored in whole data cell")
	injectedcell := flag.Bool("injectedcell", false, "Acrastruct may be injected into any place of data cell")

	debug := flag.Bool("d", false, "Turn on debug logging")
	debugServer := flag.Bool("ds", false, "Turn on http debug server")
	closeConnectionTimeout := flag.Int("close_connections_timeout", DEFAULT_ACRASERVER_WAIT_TIMEOUT, "Time that acraserver will wait (in seconds) on restart before closing all connections")

	stopOnPoison := flag.Bool("poisonshutdown", false, "Stop on detecting poison record")
	scriptOnPoison := flag.String("poisonscript", "", "Execute script on detecting poison record")

	withZone := flag.Bool("zonemode", false, "Turn on zone mode")
	enableHTTPApi := flag.Bool("enable_http_api", false, "Enable HTTP API")

	useTls := flag.Bool("tls", false, "Use tls to encrypt transport between acraserver and acraproxy/client")
	tlsKey := flag.String("tls_key", "", "Path to tls server key")
	tlsCert := flag.String("tls_cert", "", "Path to tls server certificate")
	tlsCA := flag.String("tls_ca", "", "Path to root certificate")
	tlsSNI := flag.String("tls_sni", "", "Expected Server Name (SNI)")
	noEncryption := flag.Bool("no_encryption", false, "Use raw transport (tcp/unix socket) between acraserver and acraproxy/client (don't use this flag if you not connect to database with ssl/tls")
	clientId := flag.String("client_id", "", "Expected client id of acraproxy in mode without encryption")
	acraConnectionString := flag.String("connection_string", network.BuildConnectionString(cmd.DEFAULT_ACRA_CONNECTION_PROTOCOL, cmd.DEFAULT_ACRA_HOST, cmd.DEFAULT_ACRA_PORT, ""), "Connection string like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	acraAPIConnectionString := flag.String("connection_api_string", network.BuildConnectionString(cmd.DEFAULT_ACRA_CONNECTION_PROTOCOL, cmd.DEFAULT_ACRA_HOST, cmd.DEFAULT_ACRA_API_PORT, ""), "Connection string for api like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	loggingFormat := flag.String("logging_format", "", "Logging format: plaintext, json or CEF")

	useMysql := flag.Bool("mysql", false, "Handle MySQL connections")
	usePostgresql := flag.Bool("postgresql", false, "Handle Postgresql connections (default true)")

	err := cmd.Parse(DEFAULT_CONFIG_PATH)
	if err != nil {
		log.WithError(err).Errorln("can't parse args")
		os.Exit(1)
	}

	logging.CustomizeLogging(*loggingFormat, SERVICE_NAME)
	cmd.ValidateClientId(*serverId)

	if *host != cmd.DEFAULT_ACRA_HOST || *port != cmd.DEFAULT_ACRA_PORT {
		*acraConnectionString = network.BuildConnectionString("tcp", *host, *port, "")
	}
	if *commandsPort != cmd.DEFAULT_ACRA_API_PORT {
		*acraConnectionString = network.BuildConnectionString("tcp", *host, *commandsPort, "")
	}

	if *debug {
		logging.SetLogLevel(logging.LOG_DEBUG)
	} else if *verbose {
		logging.SetLogLevel(logging.LOG_VERBOSE)
	} else {
		logging.SetLogLevel(logging.LOG_DISCARD)
	}
	if *dbHost == "" {
		log.Errorln("you must specify db_host")
		flag.Usage()
		return
	}

	if err := config.SetMySQL(*useMysql); err != nil {
		log.WithError(err).Errorln("can't set MySQL support")
		os.Exit(1)
	}
	if err := config.SetPostgresql(*usePostgresql); err != nil {
		log.WithError(err).Errorln("can't set PostgreSQL support")
		os.Exit(1)
	}

	// now it's stub as default values
	config.SetStopOnPoison(*stopOnPoison)
	config.SetScriptOnPoison(*scriptOnPoison)
	config.SetWithZone(*withZone)
	config.SetDBHost(*dbHost)
	config.SetDBPort(*dbPort)
	config.SetProxyHost(*host)
	config.SetProxyPort(*port)
	config.SetProxyCommandsPort(*commandsPort)
	config.SetKeysDir(*keysDir)
	config.SetServerId([]byte(*serverId))
	config.SetAcraConnectionString(*acraConnectionString)
	config.SetAcraAPIConnectionString(*acraAPIConnectionString)
	config.SetTLSServerCertPath(*tlsCert)
	config.SetTLSServerKeyPath(*tlsKey)
	config.SetWholeMatch(!(*injectedcell))
	config.SetEnableHTTPApi(*enableHTTPApi)
	config.SetConfigPath(DEFAULT_CONFIG_PATH)
	config.SetDebug(*debug)
	config.SetFirewall(&firewall.Firewall{})
	if *hexFormat || !*escapeFormat {
		config.SetByteaFormat(HEX_BYTEA_FORMAT)
	} else {
		config.SetByteaFormat(ESCAPE_BYTEA_FORMAT)
	}

	keyStore, err := keystore.NewFilesystemKeyStore(*keysDir)
	if err != nil {
		log.Errorln("can't initialize keystore")
		os.Exit(1)
	}
	var tlsConfig *tls.Config
	if *useTls || *tlsKey != "" {
		tlsConfig, err = network.NewTLSConfig(*tlsSNI, *tlsCA, *tlsKey, *tlsCert)
		if err != nil {
			log.WithError(err).Errorln("can't get config for TLS")
			os.Exit(1)
		}
	}
	config.SetTLSConfig(tlsConfig)
	if *useTls {
		log.Println("use TLS transport wrapper")
		config.ConnectionWrapper, err = network.NewTLSConnectionWrapper([]byte(*clientId), tlsConfig)
		if err != nil {
			log.Errorln("can't initialize tls connection wrapper")
			os.Exit(1)
		}
	} else if *noEncryption {
		if *clientId == "" && !*withZone {
			log.Errorln("without zone mode and without encryption you must set <client_id> which will be used to connect from acraproxy to acraserver")
			os.Exit(1)
		}
		log.Println("use raw transport wrapper")
		config.ConnectionWrapper = &network.RawConnectionWrapper{ClientId: []byte(*clientId)}
	} else {
		log.Println("use Secure Session transport wrapper")
		config.ConnectionWrapper, err = network.NewSecureSessionConnectionWrapper(keyStore)
		if err != nil {
			log.Errorln("can't initialize secure session connection wrapper")
			os.Exit(1)
		}
	}

	sigHandlerSIGTERM, err := cmd.NewSignalHandler([]os.Signal{os.Interrupt, syscall.SIGTERM})
	errorSignalChannel = sigHandlerSIGTERM.GetChannel()
	if err != nil {
		log.WithError(err).Errorln("can't register SIGTERM handler")
		os.Exit(1)
	}

	sigHandlerSIGHUP, err := cmd.NewSignalHandler([]os.Signal{syscall.SIGHUP})
	restartSignalsChannel = sigHandlerSIGHUP.GetChannel()
	if err != nil {
		log.WithError(err).Errorln("can't register SIGHUP handler")
		os.Exit(1)
	}

	var server *SServer
	server, err = NewServer(config, keyStore, errorSignalChannel, restartSignalsChannel)
	if err != nil {
		panic(err)
	}

	if os.Getenv(GRACEFUL_ENV) == "true" {
		server.fddACRA = DESCRIPTOR_ACRA
		server.fdAPI = DESCRIPTOR_API
	}

	if *debugServer {
		//start http server for pprof
		go func() {
			err := http.ListenAndServe("127.0.0.1:6060", nil)
			if err != nil {
				log.WithError(err).Errorln("error from debug server")
			}
		}()
	}

	go sigHandlerSIGTERM.Register()
	sigHandlerSIGTERM.AddCallback(func() {
		log.Infoln("Incoming SIGTERM or SIGINT")
		// Stop accepting new connections
		server.StopListeners()
		// Wait a maximum of N seconds for existing connections to finish
		err := server.WaitWithTimeout(time.Duration(*closeConnectionTimeout) * time.Second)
		if err == ErrWaitTimeout {
			log.Warningf("Server shutdown Timeout: %d active connections will be cut", server.ConnectionsCounter())
			server.Close()
			os.Exit(1)
		}
		server.Close()
		log.Infof("Server graceful shutdown completed, bye PID: %v", os.Getpid())
		os.Exit(0)
	})

	sigHandlerSIGHUP.AddCallback(func() {
		log.Infoln("Incoming SIGHUP")

		// Stop accepting requests
		server.StopListeners()

		// Get socket file descriptor to pass it to fork
		var fdACRA, fdAPI uintptr
		fdACRA, err = network.ListenerFileDescriptor(server.listenerACRA)
		if err != nil {
			log.Fatalln("Fail to get acra-socket file descriptor:", err)
		}
		if *withZone || *enableHTTPApi {
			fdAPI, err = network.ListenerFileDescriptor(server.listenerAPI)
			if err != nil {
				log.Fatalln("Fail to get api-socket file descriptor:", err)
			}
		}

		// Set env flag for forked process
		os.Setenv(GRACEFUL_ENV, "true")
		execSpec := &syscall.ProcAttr{
			Env:   os.Environ(),
			Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd(), fdACRA, fdAPI},
		}
		// Fork new process
		var fork, err = syscall.ForkExec(os.Args[0], os.Args, execSpec)
		if err != nil {
			log.Fatalln("Fail to fork", err)
		}
		log.Infof("Server forked to PID: %v", fork)

		// Wait a maximum of N seconds for existing connections to finish
		err = server.WaitWithTimeout(time.Duration(*closeConnectionTimeout) * time.Second)
		if err == ErrWaitTimeout {
			log.Warningf("Server shutdown Timeout: %d active connections will be cut", server.ConnectionsCounter())
			os.Exit(0)
		}
		log.Infof("Server graceful restart completed, bye PID: %v", os.Getpid())

		// Stop the old server, all the connections have been closed and the new one is running
		os.Exit(0)
	})

	log.Infof("PID: %v", os.Getpid())
	if os.Getenv(GRACEFUL_ENV) == "true" {
		go server.StartFromFileDescriptor(DESCRIPTOR_ACRA)
		if *withZone || *enableHTTPApi {
			go server.StartCommandsFromFileDescriptor(DESCRIPTOR_API)
		}
	} else {
		go server.Start()
		if *withZone || *enableHTTPApi {
			go server.StartCommands()
		}
	}

	sigHandlerSIGHUP.Register()

}
