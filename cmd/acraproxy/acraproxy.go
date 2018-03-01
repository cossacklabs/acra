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

	"crypto/tls"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
)

// DEFAULT_CONFIG_PATH relative path to config which will be parsed as default
var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName("acraproxy")

func handleClientConnection(config *Config, connection net.Conn) {
	defer connection.Close()

	if !(config.disableUserCheck) {
		host, port, err := net.SplitHostPort(connection.RemoteAddr().String())
		if nil != err {
			log.WithError(err).Errorln("can't parse client remote address")
			return
		}
		if host == "127.0.0.1" {
			netstat, err := exec.Command("sh", "-c", "netstat -atlnpe | awk '/:"+port+" */ {print $7}'").Output()
			if nil != err {
				log.WithError(err).Errorln("can't get owner UID of localhost client connection")
				return
			}
			parsedNetstat := strings.Split(string(netstat), "\n")
			correctPeer := false
			userId, err := user.Current()
			if nil != err {
				log.WithError(err).Errorln("can't get current user UID")
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
				log.Errorln("client application and ssproxy need to be start from different users")
				return
			}
		}
	}

	acraConn, err := network.Dial(config.AcraConnectionString)
	if err != nil {
		log.WithError(err).Errorln("can't connect to acra")
		return
	}
	defer acraConn.Close()

	log.Infof("send client id <%v>", string(config.ClientId))

	acraConn.SetDeadline(time.Now().Add(time.Second * 2))
	acraConnWrapped, err := config.ConnectionWrapper.WrapClient(config.ClientId, acraConn)
	if err != nil {
		log.WithError(err).Errorln("can't wrap acra connection with secure session")
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
		log.Debugln("error from connection with client")
	case err = <-fromAcraErrCh:
		log.Debugln("error from connection with acra")
	}
	if err != nil {
		if err == io.EOF {
			log.Debugln("connection closed")
		} else {
			log.WithError(err).Errorln("proxy error")
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
	keysDir := flag.String("keys_dir", keystore.DEFAULT_KEY_DIR_SHORT, "Folder from which will be loaded keys")
	clientId := flag.String("client_id", "", "Client id")
	acraHost := flag.String("acra_host", "", "IP or domain to acra daemon")
	acraCommandsPort := flag.Int("acra_commands_port", cmd.DEFAULT_ACRA_API_PORT, "Port of acra http api")
	acraPort := flag.Int("acra_port", cmd.DEFAULT_ACRA_PORT, "Port of acra daemon")
	acraId := flag.String("acra_id", "acra_server", "Expected id from acraserver for Secure Session")
	verbose := flag.Bool("v", false, "Log to stdout")
	port := flag.Int("port", cmd.DEFAULT_PROXY_PORT, "Port fo acraproxy")
	commandsPort := flag.Int("command_port", cmd.DEFAULT_PROXY_API_PORT, "Port for acraproxy http api")
	withZone := flag.Bool("zonemode", false, "Turn on zone mode")
	disableUserCheck := flag.Bool("disable_user_check", false, "Disable checking that connections from app running from another user")
	useTls := flag.Bool("tls", false, "Use tls")
	noEncryption := flag.Bool("no_encryption", false, "Don't use encryption in transport")
	connectionString := flag.String("connection_string", network.BuildConnectionString(cmd.DEFAULT_PROXY_CONNECTION_PROTOCOL, cmd.DEFAULT_PROXY_HOST, cmd.DEFAULT_PROXY_PORT, ""), "Connection string like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	connectionAPIString := flag.String("connection_api_string", network.BuildConnectionString(cmd.DEFAULT_PROXY_CONNECTION_PROTOCOL, cmd.DEFAULT_PROXY_HOST, cmd.DEFAULT_PROXY_API_PORT, ""), "Connection string like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	acraConnectionString := flag.String("acra_connection_string", "", "Connection string to Acra server like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	acraApiConnectionString := flag.String("acra_api_connection_string", "", "Connection string to Acra's API like tcp://x.x.x.x:yyyy or unix:///path/to/socket")

	err := cmd.Parse(DEFAULT_CONFIG_PATH)
	if err != nil {
		log.WithError(err).Errorln("can't parse args")
		os.Exit(1)
	}

	if *port != cmd.DEFAULT_PROXY_PORT {
		*connectionString = network.BuildConnectionString(cmd.DEFAULT_PROXY_CONNECTION_PROTOCOL, cmd.DEFAULT_PROXY_HOST, *port, "")
	}
	if *commandsPort != cmd.DEFAULT_PROXY_API_PORT {
		*connectionAPIString = network.BuildConnectionString(cmd.DEFAULT_PROXY_CONNECTION_PROTOCOL, cmd.DEFAULT_PROXY_HOST, *commandsPort, "")
	}

	if *acraHost == "" && *acraConnectionString == "" {
		log.Errorln("you must pass acra_host or acra_connection_string parameter")
		os.Exit(1)
	}
	if *acraHost != "" {
		*acraConnectionString = network.BuildConnectionString(cmd.DEFAULT_ACRA_CONNECTION_PROTOCOL, *acraHost, *acraPort, "")
	}
	if *withZone {
		if *acraHost == "" && *acraApiConnectionString == "" {
			log.Errorln("you must pass acra_host or acra_api_connection_string parameter")
			os.Exit(1)
		}
		if *acraHost != "" {
			*acraApiConnectionString = network.BuildConnectionString(cmd.DEFAULT_ACRA_CONNECTION_PROTOCOL, *acraHost, *acraCommandsPort, "")
		}
	}

	cmd.ValidateClientId(*clientId)

	clientPrivateKey := fmt.Sprintf("%v%v%v", *keysDir, string(os.PathSeparator), *clientId)
	serverPublicKey := fmt.Sprintf("%v%v%v_server.pub", *keysDir, string(os.PathSeparator), *clientId)
	exists, err := utils.FileExists(clientPrivateKey)
	if !exists {
		log.Errorf("acraproxy private key %s doesn't exists", clientPrivateKey)
		os.Exit(1)
	}
	if err != nil {
		log.Errorf("can't check is exists acraproxy private key %v, got error - %v", clientPrivateKey, err)
		os.Exit(1)
	}
	exists, err = utils.FileExists(serverPublicKey)
	if !exists {
		log.Errorf("acraserver public key %s doesn't exists", serverPublicKey)
		os.Exit(1)
	}
	if err != nil {
		log.Errorf("can't check is exists acraserver public key %v, got error - %v", serverPublicKey, err)
		os.Exit(1)
	}

	if *verbose {
		cmd.SetLogLevel(cmd.LOG_VERBOSE)
	} else {
		cmd.SetLogLevel(cmd.LOG_DISCARD)
	}
	if runtime.GOOS != "linux" {
		*disableUserCheck = true
	}

	keyStore, err := keystore.NewProxyFileSystemKeyStore(*keysDir, []byte(*clientId))
	if err != nil {
		log.WithError(err).Errorln("can't initialize keystore")
		os.Exit(1)
	}
	config := &Config{KeyStore: keyStore, KeysDir: *keysDir, ClientId: []byte(*clientId), AcraConnectionString: *acraConnectionString, ConnectionString: *connectionString, AcraId: []byte(*acraId), disableUserCheck: *disableUserCheck}
	listener, err := network.Listen(*connectionString)
	if err != nil {
		log.WithError(err).Errorln("can't start listen connections")
		os.Exit(1)
	}
	defer listener.Close()

	sigHandler, err := cmd.NewSignalHandler([]os.Signal{os.Interrupt, syscall.SIGTERM})
	if err != nil {
		log.WithError(err).Errorln("can't register SIGINT handler")
		os.Exit(1)
	}
	go sigHandler.Register()
	sigHandler.AddListener(listener)
	if *useTls {
		log.Infoln("use TLS transport wrapper")
		config.ConnectionWrapper, err = network.NewTLSConnectionWrapper(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			log.WithError(err).Errorln("can't initialize tls connection wrapper")
			os.Exit(1)
		}
	} else if *noEncryption {
		log.Infoln("use raw transport wrapper")
		config.ConnectionWrapper = &network.RawConnectionWrapper{ClientId: []byte(*clientId)}
	} else {
		log.Infoln("use Secure Session transport wrapper")
		config.ConnectionWrapper, err = network.NewSecureSessionConnectionWrapper(keyStore)
		if err != nil {
			log.WithError(err).Errorln("can't initialize secure session connection wrapper")
			os.Exit(1)
		}
	}
	if *withZone {
		go func() {
			// copy config and replace ports
			commandsConfig := *config
			commandsConfig.AcraConnectionString = *acraApiConnectionString

			log.Infof("start listening http api %s", *connectionAPIString)
			commandsListener, err := network.Listen(*connectionAPIString)
			if err != nil {
				log.WithError(err).Errorln("can't start listen connections to http api")
				os.Exit(1)
			}
			sigHandler.AddListener(commandsListener)
			for {
				connection, err := commandsListener.Accept()
				if err != nil {
					log.WithError(err).Errorf("can't accept new connection (%v)", connection.RemoteAddr())
					continue
				}
				// unix socket and value == '@'
				if len(connection.RemoteAddr().String()) == 1 {
					log.WithError(err).Errorf("new connection to http api: <%v>", connection.LocalAddr())
				} else {
					log.WithError(err).Errorf("new connection to http api: <%v>", connection.RemoteAddr())
				}
				go handleClientConnection(&commandsConfig, connection)
			}
		}()
	}
	log.Infof("start listening %s", *connectionString)
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.WithError(err).Errorln("can't accept new connection")
			os.Exit(1)
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("new connection to acraproxy: <%v>", connection.LocalAddr())
		} else {
			log.Infof("new connection to acraproxy: <%v>", connection.RemoteAddr())
		}
		go handleClientConnection(config, connection)
	}
}
