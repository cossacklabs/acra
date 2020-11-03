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

// Package main is entry point for AcraConnector. AcraConnector is a (separate) service running alongside
// your application — it pretends to be a database listener, relays all the requests to AcraServer,
// receives the responses, and returns them to an app, just like a normal database listener would do.
// To talk to AcraServer, you'll need to run AcraConnector on the same host as your application,
// in a separate container or as a separate user. You'll also need to route database requests to its address.
//
// https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter
package main

import (
	"context"
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

	"github.com/cossacklabs/acra/cmd"
	connector_mode "github.com/cossacklabs/acra/cmd/acra-connector/connector-mode"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
)

// Constants used by AcraConnector.
var (
	// DefaultConfigPath relative path to config which will be parsed as default
	ServiceName       = "acra-connector"
	DefaultConfigPath = utils.GetConfigPathByName(ServiceName)
)

func checkDependencies() error {
	for _, toolName := range []string{"netstat", "awk"} {
		if _, err := exec.LookPath(toolName); os.IsNotExist(err) {
			return fmt.Errorf("AcraConnector need \"%v\" tool", toolName)
		}
	}
	return nil
}

func handleClientConnection(config *Config, connection net.Conn) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(connectionProcessingTimeHistogram.WithLabelValues(dbConnectionType).Observe))
	handleConnection(config, connection)
	timer.ObserveDuration()
}

func handleAPIConnection(config *Config, connection net.Conn) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(connectionProcessingTimeHistogram.WithLabelValues(apiConnectionType).Observe))
	handleConnection(config, connection)
	timer.ObserveDuration()
}

func handleConnection(config *Config, connection net.Conn) {
	options := []trace.StartOption{trace.WithSpanKind(trace.SpanKindClient)}
	ctx := logging.SetTraceStatus(context.Background(), cmd.IsTraceToLogOn())
	options = append(options, trace.WithSampler(trace.AlwaysSample()))
	ctx, span := trace.StartSpan(ctx, "handleConnection", options...)
	defer span.End()

	logger := logging.NewLoggerWithTrace(ctx).WithField("client_id", string(config.ClientID))

	defer func() {
		logger.Infoln("Close connection with client")
		if err := connection.Close(); err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnectionToService).WithError(err).Errorln("Error on closing client's connection")
		}
	}()

	if !(config.DisableUserCheck) {
		host, port, err := net.SplitHostPort(connection.RemoteAddr().String())
		if nil != err {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
				Errorln("Can't parse client remote address")
			return
		}
		if host == "127.0.0.1" {
			netstat, err := exec.Command("sh", "-c", "netstat -atlnpe | awk '/:"+port+" */ {print $7}'").Output()
			if nil != err {
				logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
					Errorln("Can't get owner UID of localhost client connection")
				return
			}
			parsedNetstat := strings.Split(string(netstat), "\n")
			correctPeer := false
			userID, err := user.Current()
			if nil != err {
				logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
					Errorln("Can't get current user UID")
				return
			}
			logger.Infof("%v\ncur_user=%v", parsedNetstat, userID.Uid)
			for i := 0; i < len(parsedNetstat); i++ {
				if _, err := strconv.Atoi(parsedNetstat[i]); err == nil && parsedNetstat[i] != userID.Uid {
					correctPeer = true
					break
				}
			}
			if !correctPeer {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
					Errorln("Client application and ssproxy need to be start from different users")
				return
			}
		}
	}
	logger.WithField("connection_string", config.OutgoingConnectionString).Infof("Connect to AcraServer")
	acraConn, err := network.Dial(config.OutgoingConnectionString)
	if err != nil {
		msg := "Can't connect to AcraServer"
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
			Errorln(msg)
		span.SetStatus(trace.Status{Code: trace.StatusCodeUnknown, Message: msg})
		return
	}
	_, wrapSpan := trace.StartSpan(ctx, "WrapClient")
	acraConnWrapped, err := config.ConnectionWrapper.WrapClient(ctx, acraConn)
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantWrapConnection).
			Errorln("Can't wrap connection")
		span.SetStatus(trace.Status{Code: trace.StatusCodeUnknown})
		if err = acraConn.Close(); err != nil {
			logger.WithError(err).Errorf("Error on closing connection with %v", connector_mode.ModeToServiceName(config.Mode))
		}
		wrapSpan.End()
		return
	}
	wrapSpan.End()
	defer func() {
		if err := acraConnWrapped.Close(); err != nil {
			logger.WithError(err).Errorln("Error on closing wrapped connection to Acra-Server")
		}
	}()

	logger.Debugln("Send trace")
	if err := network.SendTrace(ctx, acraConnWrapped); err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTracingCantSendTrace).
			Errorln("Can't send trace data")
		span.SetStatus(trace.Status{Code: trace.StatusCodeUnknown})
		return
	}

	toAcraErrCh := make(chan error, 1)
	fromAcraErrCh := make(chan error, 1)
	go network.ProxyWithTracing(ctx, connection, acraConnWrapped, toAcraErrCh)
	go network.ProxyWithTracing(ctx, acraConnWrapped, connection, fromAcraErrCh)
	select {
	case err = <-toAcraErrCh:
		logger.Debugln("Stop to proxy Client->AcraServer")
	case err = <-fromAcraErrCh:
		logger.Debugln("Stop to proxy AcraServer->Client")
	}
	if err != nil {
		if err == io.EOF {
			logger.Debugln("Connection closed")
		} else {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
				Errorln("Connector error")
			span.SetStatus(trace.Status{Code: trace.StatusCodeUnknown})
		}
	}
	logger.Infoln("Close wrapped connection with AcraServer")
	if err := acraConnWrapped.Close(); err != nil {
		logger.WithError(err).Errorf("Error on closing wrapped connection with %s", connector_mode.ModeToServiceName(config.Mode))

	}
	if err := acraConn.Close(); err != nil {
		logger.WithError(err).Errorf("Error on closing connection with %s", connector_mode.ModeToServiceName(config.Mode))
	}
}

// Config stores AcraConnector configuration
type Config struct {
	KeysDir                  string
	ClientID                 []byte
	OutgoingServiceID        []byte
	OutgoingConnectionString string
	IncomingConnectionString string
	DisableUserCheck         bool
	KeyStore                 keystore.SecureSessionKeyStore
	ConnectionWrapper        network.ConnectionWrapper
	Mode                     connector_mode.ConnectorMode
}

func main() {
	loggingFormat := flag.String("logging_format", "plaintext", "Logging format: plaintext, json or CEF")
	keysDir := flag.String("keys_dir", keystore.DefaultKeyDirShort, "Folder from which will be loaded keys")
	clientID := flag.String("client_id", "", "Client ID")
	acraServerHost := flag.String("acraserver_connection_host", "", "IP or domain to AcraServer daemon")
	acraServerAPIPort := flag.Int("acraserver_api_connection_port", cmd.DefaultAcraServerAPIPort, "Port of Acra HTTP API")
	acraServerPort := flag.Int("acraserver_connection_port", cmd.DefaultAcraServerPort, "Port of AcraServer daemon")
	acraServerID := flag.String("acraserver_securesession_id", "acra_server", "Expected id from AcraServer for Secure Session")

	acraConnectorPort := flag.Int("incoming_connection_port", cmd.DefaultAcraConnectorPort, "Port to AcraConnector")
	acraConnectorAPIPort := flag.Int("incoming_connection_api_port", cmd.DefaultAcraConnectorAPIPort, "Port for AcraConnector HTTP API")
	acraServerEnableHTTPAPI := flag.Bool("http_api_enable", false, "Enable connection to AcraServer via HTTP API")
	disableUserCheck := flag.Bool("user_check_disable", false, "Disable checking that connections from app running from another user")
	useTLS := flag.Bool("acraserver_tls_transport_enable", false, "Use tls to encrypt transport between AcraServer and AcraConnector/client")
	tlsCA := flag.String("tls_ca", "", "Path to root certificate which will be used with system root certificates to validate AcraServer's certificate")
	tlsKey := flag.String("tls_key", "", "Path to private key that will be used in TLS handshake with AcraServer")
	tlsCert := flag.String("tls_cert", "", "Path to certificate")
	tlsAcraserverSNI := flag.String("tls_acraserver_sni", "", "Expected Server Name (SNI) from AcraServer")
	tlsAuthType := flag.Int("tls_auth", int(tls.RequireAndVerifyClientCert), "Set authentication mode that will be used in TLS connection with AcraServer/AcraTranslator. Values in range 0-4 that set auth type (https://golang.org/pkg/crypto/tls/#ClientAuthType). Default is tls.RequireAndVerifyClientCert")
	noEncryptionTransport := flag.Bool("acraserver_transport_encryption_disable", false, "Enable this flag to omit AcraConnector and connect client app to AcraServer directly using raw transport (tcp/unix socket). From security perspective please use at least TLS encryption (over tcp socket) between AcraServer and client app.")
	connectionString := flag.String("incoming_connection_string", network.BuildConnectionString(cmd.DefaultAcraConnectorConnectionProtocol, cmd.DefaultAcraConnectorHost, cmd.DefaultAcraConnectorPort, ""), "Connection string like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	connectionAPIString := flag.String("incoming_connection_api_string", network.BuildConnectionString(cmd.DefaultAcraConnectorConnectionProtocol, cmd.DefaultAcraConnectorHost, cmd.DefaultAcraConnectorAPIPort, ""), "Connection string like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	acraServerConnectionString := flag.String("acraserver_connection_string", "", "Connection string to AcraServer like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	acraServerAPIConnectionString := flag.String("acraserver_api_connection_string", "", "Connection string to Acra's API like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	prometheusAddress := flag.String("incoming_connection_prometheus_metrics_string", "", "URL (tcp://host:port) which will be used to expose Prometheus metrics (use <URL>/metrics address to pull metrics)")

	connectorModeString := flag.String("mode", "AcraServer", "Expected mode of connection. Possible values are: AcraServer or AcraTranslator. Corresponded connection host/port/string/session_id will be used.")
	acraTranslatorHost := flag.String("acratranslator_connection_host", cmd.DefaultAcraTranslatorGRPCHost, "IP or domain to AcraTranslator daemon")
	acraTranslatorPort := flag.Int("acratranslator_connection_port", cmd.DefaultAcraTranslatorGRPCPort, "Port of AcraTranslator daemon")
	acraTranslatorConnectionString := flag.String("acratranslator_connection_string", "", "Connection string to AcraTranslator like grpc://0.0.0.0:9696 or http://0.0.0.0:9595")
	acraTranslatorID := flag.String("acratranslator_securesession_id", "acra_translator", "Expected id from AcraTranslator for Secure Session")

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

	if err = checkDependencies(); err != nil {
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
	outgoingSecureSessionID := ""

	// if AcraTranslator
	if connectorMode == connector_mode.AcraTranslatorMode {
		if *acraTranslatorHost == "" && *acraTranslatorConnectionString == "" {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
				Errorln("Configuration error: you must pass acratranslator_connection_host or acratranslator_connection_string parameter")
			os.Exit(1)
		}
		if *acraTranslatorPort != cmd.DefaultAcraTranslatorGRPCPort {
			*acraTranslatorConnectionString = network.BuildConnectionString(cmd.DefaultAcraConnectorConnectionProtocol, *acraTranslatorHost, *acraTranslatorPort, "")
		}
		outgoingConnectionString = *acraTranslatorConnectionString
		outgoingSecureSessionID = *acraTranslatorID
	}

	// if AcraServer
	if connectorMode == connector_mode.AcraServerMode {
		if *acraConnectorPort != cmd.DefaultAcraConnectorPort {
			*connectionString = network.BuildConnectionString(cmd.DefaultAcraConnectorConnectionProtocol, cmd.DefaultAcraConnectorHost, *acraConnectorPort, "")
		}
		if *acraConnectorAPIPort != cmd.DefaultAcraConnectorAPIPort {
			*connectionAPIString = network.BuildConnectionString(cmd.DefaultAcraConnectorConnectionProtocol, cmd.DefaultAcraConnectorHost, *acraConnectorAPIPort, "")
		}

		if *acraServerHost == "" && *acraServerConnectionString == "" {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
				Errorln("Configuration error: you must pass acraserver_connection_host or acraserver_connection_string parameter")
			os.Exit(1)
		}
		if *acraServerHost != "" {
			*acraServerConnectionString = network.BuildConnectionString(cmd.DefaultAcraServerConnectionProtocol, *acraServerHost, *acraServerPort, "")
		}
		if *acraServerEnableHTTPAPI {
			if *acraServerHost == "" && *acraServerAPIConnectionString == "" {
				log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
					Errorln("Configuration error: you must pass acraserver_connection_host or acraserver_api_connection_string parameter")
				os.Exit(1)
			}
			if *acraServerHost != "" {
				*acraServerAPIConnectionString = network.BuildConnectionString(cmd.DefaultAcraServerConnectionProtocol, *acraServerHost, *acraServerAPIPort, "")
			}
		}

		outgoingConnectionString = *acraServerConnectionString
		outgoingSecureSessionID = *acraServerID
	}

	if runtime.GOOS != "linux" {
		*disableUserCheck = true
		log.Infof("Disabling user check, because OS is not Linux")
	}

	// --------- keystore  -----------
	log.Infof("Initializing keystore...")
	var keyStore keystore.TransportKeyStore
	if filesystemV2.IsKeyDirectory(*keysDir) {
		keyStore = openKeyStoreV2(*keysDir, []byte(*clientID), connectorMode)
	} else {
		keyStore = openKeyStoreV1(*keysDir, []byte(*clientID), connectorMode)
	}
	log.Infof("Keystore init OK")

	// --------- check keys -----------
	cmd.ValidateClientID(*clientID)

	log.Infof("Reading transport keys...")

	exists, err := keyStore.CheckIfPrivateKeyExists([]byte(*clientID))
	if !exists || err != nil {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
			Errorf("Configuration error: Can't check that AcraConnector private key exists, got error - %v", err)
		os.Exit(1)
	}
	log.Infof("Client id = %v, and client key is OK", *clientID)

	_, err = keyStore.GetPeerPublicKey([]byte(*clientID))
	if err != nil {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongConfiguration).
			Errorf("Configuration error: Can't check that %s public key exists, got error - %v", connectorMode, err)
		os.Exit(1)
	}
	log.Infof("%v public key is OK", connectorMode)

	// --------- Config  -----------
	log.Infof("Configuring transport...")
	config := &Config{KeyStore: keyStore, KeysDir: *keysDir, ClientID: []byte(*clientID), OutgoingConnectionString: outgoingConnectionString, IncomingConnectionString: *connectionString, OutgoingServiceID: []byte(outgoingSecureSessionID), DisableUserCheck: *disableUserCheck, Mode: connectorMode}
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
		config.ConnectionWrapper, err = network.NewSecureSessionConnectionWrapperWithServerID([]byte(*clientID), []byte(outgoingSecureSessionID), keyStore)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
				Errorln("Configuration error: Can't initialize secure session connection wrapper")
			os.Exit(1)
		}
	}

	if connectorMode == connector_mode.AcraServerMode {
		if *useTLS {
			log.Infof("Selecting transport: use TLS transport wrapper")

			ocspConfig, err := network.NewOCSPConfig("", "yes", "prefer")
			if err != nil {
				// Using `Fatal` since NewOCSPConfig should never fail with passed arguments
				log.WithError(err).Fatalln("Cannot create OCSP config")
			}

			crlConfig, err := network.NewCRLConfig("", "use")
			if err != nil {
				// Using `Fatal` since NewCRLConfig should never fail with passed arguments
				log.WithError(err).Fatalln("Cannot create CRL config")
			}

			ocspVerifier := network.DefaultOCSPVerifier{Config: *ocspConfig, Client: &network.DefaultOCSPClient{}}

			crlVerifier := network.DefaultCRLVerifier{Config: *crlConfig, Client: network.DefaultCRLClient{}}

			tlsConfig, err := network.NewTLSConfig(network.SNIOrHostname(*tlsAcraserverSNI, *acraServerHost), *tlsCA, *tlsKey, *tlsCert, tls.ClientAuthType(*tlsAuthType), ocspVerifier, crlVerifier)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
					Errorln("Configuration error: Can't get config for TLS")
				os.Exit(1)
			}
			config.ConnectionWrapper, err = network.NewTLSConnectionWrapper(nil, tlsConfig)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
					Errorln("Configuration error: Can't initialize TLS connection wrapper")
				os.Exit(1)
			}
		} else if *noEncryptionTransport {
			log.Infof("Selecting transport: use raw transport wrapper")
			config.ConnectionWrapper = &network.RawConnectionWrapper{ClientID: []byte(*clientID)}
		} else {
			log.Infof("Selecting transport: use Secure Session transport wrapper")
			config.ConnectionWrapper, err = network.NewSecureSessionConnectionWrapperWithServerID([]byte(*clientID), []byte(outgoingSecureSessionID), keyStore)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
					Errorln("Configuration error: Can't initialize secure session connection wrapper")
				os.Exit(1)
			}
		}
		if *acraServerEnableHTTPAPI {
			go func() {
				// copy config and replace ports
				commandsConfig := *config
				commandsConfig.OutgoingConnectionString = *acraServerAPIConnectionString

				log.Infof("Start listening HTTP API: %s", *connectionAPIString)
				commandsListener, err := network.Listen(*connectionAPIString)
				if err != nil {
					log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartListenConnections).
						Errorln("System error: Can't start listen connections to HTTP API")
					os.Exit(1)
				}
				sigHandler.AddListener(commandsListener)
				for {
					connection, err := commandsListener.Accept()
					if err != nil {
						log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantAcceptNewConnections).
							Errorf("System error: Can't accept new connection")
						continue
					}
					connectionCounter.WithLabelValues(apiConnectionType).Inc()
					// unix socket and value == '@'
					if len(connection.RemoteAddr().String()) == 1 {
						log.Infof("Got new connection to HTTP API: %v", connection.LocalAddr())
					} else {
						log.Infof("Got new connection to HTTP API: %v", connection.RemoteAddr())
					}
					go handleAPIConnection(&commandsConfig, connection)
				}
			}()
		}
	}

	// -------- START -----------
	log.Infof("Setup ready. Start listening connection %s", *connectionString)

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

	if *prometheusAddress != "" {
		registerMetrics()
		_, prometheusHTTPServer, err := cmd.RunPrometheusHTTPHandler(*prometheusAddress)
		if err != nil {
			panic(err)
		}
		log.Infof("Configured to send metrics and stats to `incoming_connection_prometheus_metrics_string`")
		sigHandler.AddCallback(func() {
			log.Infoln("Stop prometheus HTTP exporter")
			prometheusHTTPServer.Close()
		})
	}

	cmd.SetupTracing(ServiceName)

	for {
		connection, err := listener.Accept()
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantAcceptNewConnections).
				Errorln("Can't accept new connection")
			os.Exit(1)
		}
		connectionCounter.WithLabelValues(dbConnectionType).Inc()
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("Got new connection to AcraConnector: %v", connection.LocalAddr())
		} else {
			log.Infof("Got new connection to AcraConnector: %v", connection.RemoteAddr())
		}
		go handleClientConnection(config, connection)
	}
}

func openKeyStoreV1(keysDir string, clientID []byte, connectorMode connector_mode.ConnectorMode) keystore.TransportKeyStore {
	masterKey, err := keystore.GetMasterKeyFromEnvironment()
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantLoadMasterKey).
			Errorln("Cannot load master key")
		os.Exit(1)
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitPrivateKeysEncryptor).WithError(err).Errorln("Can't init scell encryptor")
		os.Exit(1)
	}
	keyStore, err := filesystem.NewConnectorFileSystemKeyStore(keysDir, clientID, scellEncryptor, connectorMode)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
			Errorln("Can't initialize keystore")
		os.Exit(1)
	}
	return keyStore
}

func openKeyStoreV2(outputDir string, clientID []byte, mode connector_mode.ConnectorMode) keystore.TransportKeyStore {
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
	keyDir, err := filesystemV2.OpenDirectoryRW(outputDir, suite)
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
			WithField("path", outputDir).Error("cannot open key directory")
		os.Exit(1)
	}
	return keystoreV2.NewConnectorKeyStore(keyDir, clientID, mode)
}
