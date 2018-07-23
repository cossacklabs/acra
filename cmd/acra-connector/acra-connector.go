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
	"github.com/cossacklabs/acra/cmd/acra-connector/connector-mode"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
)

// DEFAULT_CONFIG_PATH relative path to config which will be parsed as default
var SERVICE_NAME = "acra-connector"
var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName(SERVICE_NAME)

func checkDependencies() error {
	for _, toolName := range []string{"netstat", "awk"} {
		if _, err := exec.LookPath(toolName); os.IsNotExist(err) {
			return fmt.Errorf("AcraConnector need \"%v\" tool", toolName)
		}
	}
	return nil
}

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

	acraConn, err := network.Dial(config.OutgoingConnectionString)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
			Errorln("Can't connect to AcraServer")
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

	toAcraErrCh := make(chan error, 1)
	fromAcraErrCh := make(chan error, 1)
	go network.Proxy(connection, acraConnWrapped, toAcraErrCh)
	go network.Proxy(acraConnWrapped, connection, fromAcraErrCh)
	select {
	case err = <-toAcraErrCh:
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
			WithError(err).Errorln("Error from connection with client")
	case err = <-fromAcraErrCh:
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).WithError(err).
			Errorln("Error from connection with AcraServer")
	}
	if err != nil {
		if err == io.EOF {
			log.Debugln("Connection closed")
		} else {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
				Errorln("Connector error")
		}
		return
	}
}

type Config struct {
	KeysDir                  string
	ClientId                 []byte
	OutgoingServiceId        []byte
	OutgoingConnectionString string
	IncomingConnectionString string
	disableUserCheck         bool
	KeyStore                 keystore.SecureSessionKeyStore
	ConnectionWrapper        network.ConnectionWrapper
}

func main() {
	loggingFormat := flag.String("logging_format", "plaintext", "Logging format: plaintext, json or CEF")
	logging.CustomizeLogging(*loggingFormat, SERVICE_NAME)
	log.Infof("Starting service %v", SERVICE_NAME)

	keysDir := flag.String("keys_dir", keystore.DEFAULT_KEY_DIR_SHORT, "Folder from which will be loaded keys")
	clientId := flag.String("client_id", "", "Client id")
	acraServerHost := flag.String("acraserver_connection_host", "", "IP or domain to AcraServer daemon")
	acraServerApiPort := flag.Int("acraserver_api_connection_port", cmd.DEFAULT_ACRASERVER_API_PORT, "Port of Acra HTTP api")
	acraServerPort := flag.Int("acraserver_connection_port", cmd.DEFAULT_ACRASERVER_PORT, "Port of AcraServer daemon")
	acraServerId := flag.String("acraserver_securesession_id", "acra_server", "Expected id from AcraServer for Secure Session")
	verbose := flag.Bool("v", false, "Log to stderr")
	acraConnectorPort := flag.Int("incoming_connection_port", cmd.DEFAULT_ACRACONNECTOR_PORT, "Port to AcraConnector")
	acraConnectorApiPort := flag.Int("incoming_connection_api_port", cmd.DEFAULT_ACRACONNECTOR_API_PORT, "Port for AcraConnector HTTP api")
	acraServerEnableHTTPApi := flag.Bool("http_api_enable", false, "Enable AcraServer HTTP API")
	disableUserCheck := flag.Bool("user_check_disable", false, "Disable checking that connections from app running from another user")
	useTls := flag.Bool("acraserver_tls_transport_enable", false, "Use tls to encrypt transport between AcraServer and AcraConnector/client")
	tlsCA := flag.String("tls_ca", "", "Path to root certificate which will be used with system root certificates to validate AcraServer's certificate")
	tlsKey := flag.String("tls_key", "", "Path to private key that will be used in TLS handshake with AcraServer")
	tlsCert := flag.String("tls_cert", "", "Path to certificate")
	tlsAcraserverSNI := flag.String("tls_acraserver_sni", "", "Expected Server Name (SNI) from AcraServer")
	tlsAuthType := flag.Int("tls_auth", int(tls.RequireAndVerifyClientCert), "Set authentication mode that will be used in TLS connection with AcraServer/AcraTranslator. Values in range 0-4 that set auth type (https://golang.org/pkg/crypto/tls/#ClientAuthType). Default is tls.RequireAndVerifyClientCert")
	noEncryptionTransport := flag.Bool("acraserver_transport_encryption_disable", false, "Use raw transport (tcp/unix socket) between acraserver and acraproxy/client (don't use this flag if you not connect to database with ssl/tls")
	connectionString := flag.String("incoming_connection_string", network.BuildConnectionString(cmd.DEFAULT_ACRACONNECTOR_CONNECTION_PROTOCOL, cmd.DEFAULT_ACRACONNECTOR_HOST, cmd.DEFAULT_ACRACONNECTOR_PORT, ""), "Connection string like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	connectionAPIString := flag.String("incoming_connection_api_string", network.BuildConnectionString(cmd.DEFAULT_ACRACONNECTOR_CONNECTION_PROTOCOL, cmd.DEFAULT_ACRACONNECTOR_HOST, cmd.DEFAULT_ACRACONNECTOR_API_PORT, ""), "Connection string like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	acraServerConnectionString := flag.String("acraserver_connection_string", "", "Connection string to AcraServer like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	acraServerApiConnectionString := flag.String("acraserver_api_connection_string", "", "Connection string to Acra's API like tcp://x.x.x.x:yyyy or unix:///path/to/socket")

	connectorModeString := flag.String("mode", "AcraServer", "Expected mode of connection. Possible values are: AcraServer or AcraTranslator. Corresponded connection host/port/string/session_id will be used.")
	acraTranslatorHost := flag.String("acratranslator_connection_host", cmd.DEFAULT_ACRATRANSLATOR_GRPC_HOST, "IP or domain to AcraTranslator daemon")
	acraTranslatorPort := flag.Int("acratranslator_connection_port", cmd.DEFAULT_ACRATRANSLATOR_GRPC_PORT, "Port of AcraTranslator daemon")
	acraTranslatorConnectionString := flag.String("acratranslator_connection_string", "", "Connection string to AcraTranslator like grpc://0.0.0.0:9696 or http://0.0.0.0:9595")
	acraTranslatorId := flag.String("acratranslator_securesession_id", "acra_translator", "Expected id from AcraTranslator for Secure Session")

	err := cmd.Parse(DEFAULT_CONFIG_PATH, SERVICE_NAME)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}

	// if log format was overridden
	logging.CustomizeLogging(*loggingFormat, SERVICE_NAME)
	log.Infof("Validating service configuration")

	if err := checkDependencies(); err != nil {
		log.Infoln(err.Error())
		os.Exit(1)
	}

	connectorMode := connector_mode.CheckConnectorMode(*connectorModeString)
	if connectorMode == connector_mode.UndefinedMode {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
			Errorln("Configuration error: you must pass mode=AcraServer or mode=AcraTranslator parameter")
		os.Exit(1)
	}

	log.Infof("Preparing to start in mode: %s", connectorMode)

	outgoingConnectionString := ""
	outgoingSecureSessionId := ""

	// if AcraTranslator
	if connectorMode == connector_mode.AcraTranslatorMode {
		if *acraTranslatorHost == "" && *acraTranslatorConnectionString == "" {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
				Errorln("Configuration error: you must pass acratranslator_connection_host or acratranslator_connection_string parameter")
			os.Exit(1)
		}
		if *acraTranslatorPort != cmd.DEFAULT_ACRATRANSLATOR_GRPC_PORT {
			*acraTranslatorConnectionString = network.BuildConnectionString(cmd.DEFAULT_ACRACONNECTOR_CONNECTION_PROTOCOL, *acraTranslatorHost, *acraTranslatorPort, "")
		}
		outgoingConnectionString = *acraTranslatorConnectionString
		outgoingSecureSessionId = *acraTranslatorId
	}

	// if AcraServer
	if connectorMode == connector_mode.AcraServerMode {
		if *acraConnectorPort != cmd.DEFAULT_ACRACONNECTOR_PORT {
			*connectionString = network.BuildConnectionString(cmd.DEFAULT_ACRACONNECTOR_CONNECTION_PROTOCOL, cmd.DEFAULT_ACRACONNECTOR_HOST, *acraConnectorPort, "")
		}
		if *acraConnectorApiPort != cmd.DEFAULT_ACRACONNECTOR_API_PORT {
			*connectionAPIString = network.BuildConnectionString(cmd.DEFAULT_ACRACONNECTOR_CONNECTION_PROTOCOL, cmd.DEFAULT_ACRACONNECTOR_HOST, *acraConnectorApiPort, "")
		}

		if *acraServerHost == "" && *acraServerConnectionString == "" {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
				Errorln("Configuration error: you must pass acraserver_connection_host or acraserver_connection_string parameter")
			os.Exit(1)
		}
		if *acraServerHost != "" {
			*acraServerConnectionString = network.BuildConnectionString(cmd.DEFAULT_ACRA_CONNECTION_PROTOCOL, *acraServerHost, *acraServerPort, "")
		}
		if *acraServerEnableHTTPApi {
			if *acraServerHost == "" && *acraServerApiConnectionString == "" {
				log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
					Errorln("Configuration error: you must pass acraserver_connection_host or acra_api_connection_string parameter")
				os.Exit(1)
			}
			if *acraServerHost != "" {
				*acraServerApiConnectionString = network.BuildConnectionString(cmd.DEFAULT_ACRA_CONNECTION_PROTOCOL, *acraServerHost, *acraServerApiPort, "")
			}
		}

		outgoingConnectionString = *acraServerConnectionString
		outgoingSecureSessionId = *acraServerId
	}

	if runtime.GOOS != "linux" {
		*disableUserCheck = true
		log.Infof("Disabling user check, because OS is not Linux")
	}

	// --------- keystore  -----------
	log.Infof("Initializing keystore...")
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
	keyStore, err := filesystem.NewConnectorFileSystemKeyStore(*keysDir, []byte(*clientId), scellEncryptor, connectorMode)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
			Errorln("Can't initialize keystore")
		os.Exit(1)
	}
	log.Infof("Keystore init OK")

	// --------- check keys -----------
	cmd.ValidateClientId(*clientId)

	log.Infof("Reading keys...")

	exists, err := keyStore.CheckIfPrivateKeyExists([]byte(*clientId))
	if !exists || err != nil {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
			Errorf("Configuration error: can't check that AcraConnector private key exists, got error - %v", err)
		os.Exit(1)
	}
	log.Infof("Client id and client key is OK")

	_, err = keyStore.GetPeerPublicKey([]byte(*clientId))
	if err != nil {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
			Errorf("Configuration error: can't check that %s public key exists, got error - %v", connectorMode, err)
		os.Exit(1)
	}
	log.Infof("%v public key is OK", connectorMode)

	// --------- Config  -----------
	log.Infof("Configuring transport...")
	config := &Config{KeyStore: keyStore, KeysDir: *keysDir, ClientId: []byte(*clientId), OutgoingConnectionString: outgoingConnectionString, IncomingConnectionString: *connectionString, OutgoingServiceId: []byte(outgoingSecureSessionId), disableUserCheck: *disableUserCheck}
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

	// -------- TRANSPORT -----------
	if connectorMode == connector_mode.AcraTranslatorMode {
		log.Infof("Selecting transport: use Secure Session transport wrapper")
		config.ConnectionWrapper, err = network.NewSecureSessionConnectionWrapper(keyStore)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
				Errorln("Configuration error: can't initialize secure session connection wrapper")
			os.Exit(1)
		}
	}

	if connectorMode == connector_mode.AcraServerMode {
		if *useTls {
			log.Infof("Selecting transport: use TLS transport wrapper")
			tlsConfig, err := network.NewTLSConfig(network.SNIOrHostname(*tlsAcraserverSNI, *acraServerHost), *tlsCA, *tlsKey, *tlsCert, tls.ClientAuthType(*tlsAuthType))
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
		} else if *noEncryptionTransport {
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
		if *acraServerEnableHTTPApi {
			go func() {
				// copy config and replace ports
				commandsConfig := *config
				commandsConfig.OutgoingConnectionString = *acraServerApiConnectionString

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
	}

	// -------- START -----------
	log.Infof("Setup ready. Start listening connection %s", *connectionString)

	if *verbose {
		logging.SetLogLevel(logging.LOG_VERBOSE)
	} else {
		log.Infof("Disabling future logs.. Set -v to see logs")
		logging.SetLogLevel(logging.LOG_DISCARD)
	}

	for {
		connection, err := listener.Accept()
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantAcceptNewConnections).
				Errorln("System error: сan't accept new connection")
			os.Exit(1)
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("Got new connection to AcraConnector: %v", connection.LocalAddr())
		} else {
			log.Infof("Got new connection to AcraConnector: %v", connection.RemoteAddr())
		}
		go handleClientConnection(config, connection)
	}
}
