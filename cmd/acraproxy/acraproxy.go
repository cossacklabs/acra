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
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"bytes"
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/session"
)

const (
	MIN_LENGTH_CLIENT_ID = 4
	MAX_LENGTH_CLIENT_ID = 256
)

// DEFAULT_CONFIG_PATH relative path to config which will be parsed as default
var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName("acraproxy")

type ClientSession struct {
	Config *Config
}

func (session *ClientSession) StateChanged(ss *session.SecureSession, state int) {}

func (client_session *ClientSession) GetPublicKeyForId(ss *session.SecureSession, id []byte) *keys.PublicKey {
	if bytes.Compare(client_session.Config.AcraId, id) != 0 {
		log.Printf("Warning: incorrect server id - %v\n", string(id))
		return nil
	}
	log.Printf("Debug: use %v server's public key\n", fmt.Sprintf("%v/%v_server.pub", client_session.Config.KeysDir, string(client_session.Config.ClientId)))
	// try to open file in PUBLIC_KEYS_DIR directory where pub file should be named like <client_id>.pub
	key, _ := utils.LoadPublicKey(fmt.Sprintf("%v/%v_server.pub", client_session.Config.KeysDir, string(client_session.Config.ClientId)))
	return key
}

func NewClientSession(config *Config) (*session.SecureSession, error) {
	log.Printf("Debug: use private key: %v\n", fmt.Sprintf("%v/%v", config.KeysDir, string(config.ClientId)))
	privateKey, err := utils.LoadPrivateKey(fmt.Sprintf("%v/%v", config.KeysDir, string(config.ClientId)))
	if err != nil {
		return nil, err
	}
	ssession, err := session.New(config.ClientId, privateKey, &ClientSession{Config: config})
	if err != nil {
		return nil, err
	}
	return ssession, nil
}

func initializeSecureSession(config *Config, connection net.Conn) (*session.SecureSession, error) {
	err := utils.SendSessionData(config.ClientId, connection)
	if err != nil {
		return nil, err
	}
	log.Println("Debug: create ssession")
	ssession, err := NewClientSession(config)
	if err != nil {
		return nil, err
	}
	connectRequest, err := ssession.ConnectRequest()
	if err != nil {
		return nil, err
	}
	err = utils.SendSessionData(connectRequest, connection)
	if err != nil {
		return nil, err
	}
	for {
		data, err := utils.ReadSessionData(connection)
		if err != nil {
			return nil, err
		}
		buf, sendPeer, err := ssession.Unwrap(data)
		if nil != err {
			return nil, err
		}

		if !sendPeer {
			log.Println("Debug: initialized secure session")
			return ssession, nil
		}

		err = utils.SendSessionData(buf, connection)
		if err != nil {
			return nil, err
		}

		if ssession.GetState() == session.STATE_ESTABLISHED {
			return ssession, nil
		}
	}
}

func proxyClientConnections(clientConnection, acraConnection net.Conn, session *session.SecureSession, errCh chan<- error) {
	// postgresql usually use 8kb for buffers
	buf := make([]byte, 8192)
	for {
		n, err := clientConnection.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		encryptedData, err := session.Wrap(buf[:n])
		if err != nil {
			errCh <- err
			return
		}
		err = utils.SendData(encryptedData, acraConnection)
		if err != nil {
			errCh <- err
			return
		}
		if n == 8192 {
			log.Printf("Debug: used full acraproxy buffer. Increase size to 2x from %v to %v\n", len(buf), len(buf)*2)
			buf = make([]byte, len(buf)*2)
		}
	}
}

func proxyAcraConnections(clientConnection, acraConnection net.Conn, session *session.SecureSession, errCh chan<- error) {
	for {
		data, err := utils.ReadData(acraConnection)
		if err != nil {
			errCh <- err
			return
		}
		decryptedData, _, err := session.Unwrap(data)
		if err != nil {
			errCh <- err
			return
		}
		n, err := clientConnection.Write(decryptedData)
		if err != nil {
			errCh <- err
			return
		}
		if n != len(decryptedData) {
			errCh <- errors.New("sent incorrect bytes count")
			return
		}
	}
}

func handleClientConnection(config *Config, connection net.Conn) {
	defer connection.Close()

	if !(config.disableUserCheck) {
		host, port, err := net.SplitHostPort(connection.RemoteAddr().String())
		if nil != err {
			log.Printf("Error: %v\n", utils.ErrorMessage("can't parse client remote address", err))
			return
		}
		if host == "127.0.0.1" {
			netstat, err := exec.Command("sh", "-c", "netstat -atlnpe | awk '/:"+port+" */ {print $7}'").Output()
			if nil != err {
				log.Printf("Error: %v\n", utils.ErrorMessage("can't get owner UID of localhost client connection", err))
				return
			}
			parsedNetstat := strings.Split(string(netstat), "\n")
			correctPeer := false
			userId, err := user.Current()
			if nil != err {
				log.Printf("Error: %v\n", utils.ErrorMessage("can't get current user UID", err))
				return
			}
			fmt.Printf("Info: %v\ncur_user=%v\n", parsedNetstat, userId.Uid)
			for i := 0; i < len(parsedNetstat); i++ {
				if _, err := strconv.Atoi(parsedNetstat[i]); err == nil && parsedNetstat[i] != userId.Uid {
					correctPeer = true
					break
				}
			}
			if !correctPeer {
				log.Println("Error: client application and ssproxy need to be start from different users")
				return
			}
		}
	}

	acraConn, err := net.Dial("tcp", fmt.Sprintf("%v:%v", config.AcraHost, config.AcraPort))
	if err != nil {
		log.Printf("Error: %v\n", utils.ErrorMessage("can't connect to acra", err))
		return
	}
	defer acraConn.Close()
	ssession, err := initializeSecureSession(config, acraConn)
	if err != nil {
		log.Printf("Error: %v\n", utils.ErrorMessage("can't initialize secure session", err))
		return
	}
	errCh := make(chan error)
	log.Println("Debug: secure session initialized")
	go proxyClientConnections(connection, acraConn, ssession, errCh)
	go proxyAcraConnections(connection, acraConn, ssession, errCh)
	err = <-errCh
	if err != nil {
		if err == io.EOF {
			log.Println("Debug: connection closed")
		} else {
			log.Println("Error: ", err)
		}
		return
	}
}

type Config struct {
	KeysDir          string
	ClientId         []byte
	AcraId           []byte
	AcraHost         string
	AcraPort         int
	Port             int
	disableUserCheck bool
}

func main() {
	keysDir := flag.String("keys_dir", keystore.DEFAULT_KEY_DIR_SHORT, "Folder from which will be loaded keys")
	clientId := flag.String("client_id", "", "Client id")
	acraHost := flag.String("acra_host", "", "IP or domain to acra daemon")
	acraCommandsPort := flag.Int("acra_commands_port", 9090, "Port of acra http api")
	acraPort := flag.Int("acra_port", 9393, "Port of acra daemon")
	acraId := flag.String("acra_id", "acra_server", "Expected id from acraserver for Secure Session")
	verbose := flag.Bool("v", false, "Log to stdout")
	port := flag.Int("port", 9494, "Port fo acraproxy")
	commandsPort := flag.Int("command_port", 9191, "Port for acraproxy http api")
	withZone := flag.Bool("zonemode", false, "Turn on zone mode")
	disableUserCheck := flag.Bool("disable_user_check", false, "Disable checking that connections from app running from another user")

	err := cmd.Parse(DEFAULT_CONFIG_PATH)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("Can't parse args", err))
		os.Exit(1)
	}

	if len(*clientId) <= MIN_LENGTH_CLIENT_ID {
		fmt.Printf("Error: client id length <= %v. Use longer than %v\n", MIN_LENGTH_CLIENT_ID, MIN_LENGTH_CLIENT_ID)
		flag.Usage()
		os.Exit(1)
	}
	if len(*clientId) >= MAX_LENGTH_CLIENT_ID {
		fmt.Printf("Error: client id length >= %v. Use less than %v\n", MAX_LENGTH_CLIENT_ID, MAX_LENGTH_CLIENT_ID)
		flag.Usage()
		os.Exit(1)
	}
	clientPrivateKey := fmt.Sprintf("%v%v%v", *keysDir, string(os.PathSeparator), *clientId)
	serverPublicKey := fmt.Sprintf("%v%v%v_server.pub", *keysDir, string(os.PathSeparator), *clientId)
	exists, err := utils.FileExists(clientPrivateKey)
	if !exists {
		fmt.Printf("Error: acraproxy private key %s doesn't exists\n", clientPrivateKey)
		os.Exit(1)
	}
	if err != nil {
		fmt.Printf("Error: can't check is exists acraproxy private key %v, got error - %v\n", clientPrivateKey, err)
		os.Exit(1)
	}
	exists, err = utils.FileExists(serverPublicKey)
	if !exists {
		fmt.Printf("Error: acraserver public key %s doesn't exists\n", serverPublicKey)
		os.Exit(1)
	}
	if err != nil {
		fmt.Printf("Error: can't check is exists acraserver public key %v, got error - %v\n", serverPublicKey, err)
		os.Exit(1)
	}
	if *acraHost == "" {
		fmt.Println("Error: you must specify host to acra")
		flag.Usage()
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
	config := &Config{KeysDir: *keysDir, ClientId: []byte(*clientId), AcraHost: *acraHost, AcraPort: *acraPort, Port: *port, AcraId: []byte(*acraId), disableUserCheck: *disableUserCheck}
	listener, err := net.Listen("tcp", fmt.Sprintf(":%v", *port))
	if err != nil {
		log.Printf("Error: %v\n", utils.ErrorMessage("can't start listen connections", err))
		os.Exit(1)
	}
	if *withZone {
		go func() {
			commandsConfig := &Config{KeysDir: *keysDir, ClientId: []byte(*clientId), AcraHost: *acraHost, AcraPort: *acraCommandsPort, Port: *commandsPort, AcraId: []byte(*acraId), disableUserCheck: *disableUserCheck}
			log.Printf("Info: start listening http api %v\n", *commandsPort)
			commandsListener, err := net.Listen("tcp", fmt.Sprintf(":%v", *commandsPort))
			if err != nil {
				log.Printf("Error: %v\n", utils.ErrorMessage("can't start listen connections to http api", err))
				os.Exit(1)
			}
			for {
				connection, err := commandsListener.Accept()
				if err != nil {
					log.Printf("Error: %v\n", utils.ErrorMessage(fmt.Sprintf("can't accept new connection (%v)", connection.RemoteAddr()), err))
					continue
				}
				log.Printf("Info: new connection to http api: %v\n", connection.RemoteAddr())
				go handleClientConnection(commandsConfig, connection)
			}
		}()
	}
	log.Printf("Info: start listening %v\n", *port)
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Printf("Error: %v\n", utils.ErrorMessage("can't accept new connection", err))
			os.Exit(1)
		}
		log.Printf("Info: new connection: %v\n", connection.RemoteAddr())
		go handleClientConnection(config, connection)
	}
}
