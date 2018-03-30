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
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
)

// DEFAULT_CONFIG_PATH relative path to config which will be parsed as default
var SERVICE_NAME = "acraproxy"
var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName(SERVICE_NAME)

func handleClientConnection(config *Config, connection net.Conn) {
	defer connection.Close()

	if !(config.disableUserCheck) {
		host, port, err := net.SplitHostPort(connection.RemoteAddr().String())
		if nil != err {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
				Errorln("Can't parse client remote address")
			return
		}
		if host == "127.0.0.1" {
			netstat, err := exec.Command("sh", "-c", "netstat -atlnpe | awk '/:"+port+" */ {print $7}'").Output()
			if nil != err {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
					Errorln("Can't get owner UID of localhost client connection")
				return
			}
			parsedNetstat := strings.Split(string(netstat), "\n")
			correctPeer := false
			userId, err := user.Current()
			if nil != err {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
					Errorln("Can't get current user UID")
				return
			}
			log.Infof("%v\ncur_user=%v", parsedNetstat, userId.Uid)
			for i := 0; i < len(parsedNetstat); i++ {
				if _, err := strconv.Atoi(parsedNetstat[i]); err == nil && parsedNetstat[i] != userId.Uid {
					correctPeer = true
					break
				}
			}
			if !correctPeer {
				log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
					Errorln("Client application and ssproxy need to be start from different users")
				return
			}
		}
	}

	acraConn, err := network.Dial(config.AcraConnectionString)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
			Errorln("Can't connect to acra")
		return
	}
	defer acraConn.Close()

	acraConn.SetDeadline(time.Now().Add(time.Second * 2))
	acraConnWrapped, err := config.ConnectionWrapper.WrapClient(config.ClientId, acraConn)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantWrapConnection).
			Errorln("Can't wrap connection")
		return
	}
	acraConn.SetDeadline(time.Time{})
	defer acraConnWrapped.Close()

	toAcraErrCh := make(chan error)
	fromAcraErrCh := make(chan error)
	go network.Proxy(connection, acraConnWrapped, toAcraErrCh)
	go network.Proxy(acraConnWrapped, connection, fromAcraErrCh)
	select {
	case err = <-toAcraErrCh:
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
			Errorln("Error from connection with client")
	case err = <-fromAcraErrCh:
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
			Errorln("Error from connection with acra")
	}
	if err != nil {
		if err == io.EOF {
			log.Debugln("Connection closed")
		} else {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
				Errorln("Proxy error")
		}
		return
	}
}

type Config struct {
	KeysDir              string
	ClientId             []byte
	AcraId               []byte
	AcraConnectionString string
	ConnectionString     string
	disableUserCheck     bool
	KeyStore             keystore.SecureSessionKeyStore
	ConnectionWrapper    network.ConnectionWrapper
}

func main() {
	loggingFormat := flag.String("logging_format", "plaintext", "Logging format: plaintext, json or CEF")
	logging.CustomizeLogging(*loggingFormat, SERVICE_NAME)
	log.Infof("Starting service")

	keysDir := flag.String("keys_dir", keystore.DEFAULT_KEY_DIR_SHORT, "Folder from which will be loaded keys")
	clientId := flag.String("client_id", "", "Client id")
	acraHost := flag.String("acra_host", "", "IP or domain to acra daemon")
	acraCommandsPort := flag.Int("acra_commands_port", cmd.DEFAULT_ACRA_API_PORT, "Port of acra http api")
	acraPort := flag.Int("acra_port", cmd.DEFAULT_ACRA_PORT, "Port of acra daemon")
	acraId := flag.String("acra_id", "acra_server", "Expected id from acraserver for Secure Session")
	verbose := flag.Bool("v", false, "Log to stderr")
	port := flag.Int("port", cmd.DEFAULT_PROXY_PORT, "Port fo acraproxy")
	commandsPort := flag.Int("command_port", cmd.DEFAULT_PROXY_API_PORT, "Port for acraproxy http api")
	enableHTTPApi := flag.Bool("enable_http_api", false, "Enable HTTP API")
	disableUserCheck := flag.Bool("disable_user_check", false, "Disable checking that connections from app running from another user")
	useTls := flag.Bool("tls", false, "Use tls to encrypt transport between acraserver and acraproxy/client")
	tlsCA := flag.String("tls_ca", "", "Path to root certificate")
	tlsKey := flag.String("tls_key", "", "Path to tls client's key")
	tlsCert := flag.String("tls_cert", "", "Path to tls client's certificate")
	tlsSNI := flag.String("tls_sni", "", "Expected Server Name (SNI)")
	noEncryption := flag.Bool("no_encryption", false, "Use raw transport (tcp/unix socket) between acraserver and acraproxy/client (don't use this flag if you not connect to database with ssl/tls")
	connectionString := flag.String("connection_string", network.BuildConnectionString(cmd.DEFAULT_PROXY_CONNECTION_PROTOCOL, cmd.DEFAULT_PROXY_HOST, cmd.DEFAULT_PROXY_PORT, ""), "Connection string like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	connectionAPIString := flag.String("connection_api_string", network.BuildConnectionString(cmd.DEFAULT_PROXY_CONNECTION_PROTOCOL, cmd.DEFAULT_PROXY_HOST, cmd.DEFAULT_PROXY_API_PORT, ""), "Connection string like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	acraConnectionString := flag.String("acra_connection_string", "", "Connection string to Acra server like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	acraApiConnectionString := flag.String("acra_api_connection_string", "", "Connection string to Acra's API like tcp://x.x.x.x:yyyy or unix:///path/to/socket")

	err := cmd.Parse(DEFAULT_CONFIG_PATH)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}

	// if log format was overridden
	logging.CustomizeLogging(*loggingFormat, SERVICE_NAME)
	log.Infof("Validating service configuration")

	if *port != cmd.DEFAULT_PROXY_PORT {
		*connectionString = network.BuildConnectionString(cmd.DEFAULT_PROXY_CONNECTION_PROTOCOL, cmd.DEFAULT_PROXY_HOST, *port, "")
	}
	if *commandsPort != cmd.DEFAULT_PROXY_API_PORT {
		*connectionAPIString = network.BuildConnectionString(cmd.DEFAULT_PROXY_CONNECTION_PROTOCOL, cmd.DEFAULT_PROXY_HOST, *commandsPort, "")
	}

	if *acraHost == "" && *acraConnectionString == "" {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
			Errorln("Configuration error: you must pass acra_host or acra_connection_string parameter")
		os.Exit(1)
	}
	if *acraHost != "" {
		*acraConnectionString = network.BuildConnectionString(cmd.DEFAULT_ACRA_CONNECTION_PROTOCOL, *acraHost, *acraPort, "")
	}
	if *enableHTTPApi {
		if *acraHost == "" && *acraApiConnectionString == "" {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
				Errorln("Configuration error: you must pass acra_host or acra_api_connection_string parameter")
			os.Exit(1)
		}
		if *acraHost != "" {
			*acraApiConnectionString = network.BuildConnectionString(cmd.DEFAULT_ACRA_CONNECTION_PROTOCOL, *acraHost, *acraCommandsPort, "")
		}
	}

	cmd.ValidateClientId(*clientId)

	log.Infof("Reading keys")
	clientPrivateKey := fmt.Sprintf("%v%v%v", *keysDir, string(os.PathSeparator), *clientId)
	serverPublicKey := fmt.Sprintf("%v%v%v_server.pub", *keysDir, string(os.PathSeparator), *clientId)
	exists, err := utils.FileExists(clientPrivateKey)
	if !exists {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
			Errorf("Configuration error: acraproxy private key %s doesn't exists", clientPrivateKey)
		os.Exit(1)
	}
	if err != nil {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
			Errorf("Configuration error: can't check is exists acraproxy private key %v, got error - %v", clientPrivateKey, err)
		os.Exit(1)
	}
	exists, err = utils.FileExists(serverPublicKey)
	if !exists {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
			Errorf("Configuration error: acraserver public key %s doesn't exists", serverPublicKey)
		os.Exit(1)
	}
	if err != nil {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
			Errorf("Configuration error: can't check is exists acraserver public key %v, got error - %v", serverPublicKey, err)
		os.Exit(1)
	}

	if *verbose {
		logging.SetLogLevel(logging.LOG_VERBOSE)
	} else {
		logging.SetLogLevel(logging.LOG_DISCARD)
	}
	if runtime.GOOS != "linux" {
		*disableUserCheck = true
	}

	log.Infof("Initializing keystore")
	keyStore, err := keystore.NewProxyFileSystemKeyStore(*keysDir, []byte(*clientId))
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
			Errorln("Can't initialize keystore")
		os.Exit(1)
	}

	log.Debugf("Start listening connections")
	config := &Config{KeyStore: keyStore, KeysDir: *keysDir, ClientId: []byte(*clientId), AcraConnectionString: *acraConnectionString, ConnectionString: *connectionString, AcraId: []byte(*acraId), disableUserCheck: *disableUserCheck}
	listener, err := network.Listen(*connectionString)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartListenConnections).
			Errorln("Can't start listen connections")
		os.Exit(1)
	}
	defer listener.Close()

	log.Debugf("Registering process signal handlers")
	sigHandler, err := cmd.NewSignalHandler([]os.Signal{os.Interrupt, syscall.SIGTERM})
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantRegisterSignalHandler).
			Errorln("Can't register SIGINT handler")
		os.Exit(1)
	}
	go sigHandler.Register()
	sigHandler.AddListener(listener)


	if *useTls {
		log.Infof("Selecting transport: use TLS transport wrapper")
		tlsConfig, err := network.NewTLSConfig(*tlsSNI, *tlsCA, *tlsKey, *tlsCert)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
				Errorln("Configuration error: can't get config for TLS")
			os.Exit(1)
		}
		config.ConnectionWrapper, err = network.NewTLSConnectionWrapper(nil, tlsConfig)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
				Errorln("Configuration error: can't initialize TLS connection wrapper")
			os.Exit(1)
		}
	} else if *noEncryption {
		log.Infof("Selecting transport: use raw transport wrapper")
		config.ConnectionWrapper = &network.RawConnectionWrapper{ClientId: []byte(*clientId)}
	} else {
		log.Infof("Selecting transport: use Secure Session transport wrapper")
		config.ConnectionWrapper, err = network.NewSecureSessionConnectionWrapper(keyStore)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
				Errorln("Configuration error: can't initialize secure session connection wrapper")
			os.Exit(1)
		}
	}
	if *enableHTTPApi {
		go func() {
			// copy config and replace ports
			commandsConfig := *config
			commandsConfig.AcraConnectionString = *acraApiConnectionString

			log.Infof("Start listening http API: %s", *connectionAPIString)
			commandsListener, err := network.Listen(*connectionAPIString)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartListenConnections).
				Errorln("System error: can't start listen connections to http API")
				os.Exit(1)
			}
			sigHandler.AddListener(commandsListener)
			for {
				connection, err := commandsListener.Accept()
				if err != nil {
					log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantAcceptNewConnections).
						Errorf("System error: can't accept new connection")
					continue
				}
				// unix socket and value == '@'
				if len(connection.RemoteAddr().String()) == 1 {
					log.Infof("Got new connection to http API: %v", connection.LocalAddr())
				} else {
					log.Infof("Got new connection to http API: %v", connection.RemoteAddr())
				}
				go handleClientConnection(&commandsConfig, connection)
			}
		}()
	}

	log.Infof("Start listening connection %s", *connectionString)
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantAcceptNewConnections).
				Errorln("System error: сan't accept new connection")
			os.Exit(1)
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("Got new connection to acraproxy: %v", connection.LocalAddr())
		} else {
			log.Infof("Got new connection to acraproxy: %v", connection.RemoteAddr())
		}
		go handleClientConnection(config, connection)
	}
}
