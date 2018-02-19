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
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"


	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/network"
	"crypto/tls"
)

// DEFAULT_CONFIG_PATH relative path to config which will be parsed as default
var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName("acraproxy")



func handleClientConnection(config *Config, connection net.Conn) {
	defer func(){
		log.Println("acraproxy connection close")
		connection.Close()
		log.Println("acraproxy connection closed")
	}()

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
	defer func(){
		log.Println("close acraConn")
		acraConn.Close()
		log.Println("closed acraConn")
	}()

	log.Printf("Info: send client id <%v>\n", string(config.ClientId))
	err = utils.SendData(config.ClientId, acraConn)
	if err != nil {
		acraConn.Close()
		log.Println("failed sending client id")
		return
	}
	//acraConn.SetDeadline(time.Now().Add(time.Second*2))
	acraConnWrapped, err := config.ConnectionWrapper.WrapClient(config.ClientId, acraConn)
	if err != nil{
		log.Printf("Error: %v\n", utils.ErrorMessage("can't wrap acra connection with secure session", err))
		return
	}
	log.Println("connection wrapped")
	//acraConn.SetDeadline(time.Time{})
	defer func(){
		log.Println("close acraConnWrapped")
		acraConnWrapped.Close()
		log.Println("closed acraConnWrapped")
	}()

	toAcraErrCh:= make(chan error)
	fromAcraErrCh := make(chan error)
	log.Println("Debug: secure session initialized")
	go network.Proxy(connection, acraConnWrapped, toAcraErrCh)
	go network.Proxy(acraConnWrapped, connection, fromAcraErrCh)
	select{
	case err = <-toAcraErrCh:
		log.Println("to acra chan err")
	case err = <- fromAcraErrCh:
		log.Println("from acra chan err")
	}
	if err != nil {
		if err == io.EOF {
			log.Println("Debug: connection closed")
		} else {
			log.Println("Error: ", err)
		}
		return
	}
	log.Println("err == nil")
}

type Config struct {
	KeysDir          string
	ClientId         []byte
	AcraId           []byte
	AcraHost         string
	AcraPort         int
	Port             int
	disableUserCheck bool
	KeyStore keystore.SecureSessionKeyStore
	ConnectionWrapper network.ConnectionWrapper
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
	useTls := flag.Bool("tls", false, "Use tls")

	log.SetPrefix("Acraproxy: ")

	err := cmd.Parse(DEFAULT_CONFIG_PATH)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("Can't parse args", err))
		os.Exit(1)
	}

	cmd.ValidateClientId(*clientId)

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

	keyStore, err := keystore.NewProxyFileSystemKeyStore(*keysDir, []byte(*clientId))
	if err != nil{
		log.Println("Error: can't initialize keystore")
		os.Exit(1)
	}
	config := &Config{KeyStore: keyStore, KeysDir: *keysDir, ClientId: []byte(*clientId), AcraHost: *acraHost, AcraPort: *acraPort, Port: *port, AcraId: []byte(*acraId), disableUserCheck: *disableUserCheck}
	listener, err := net.Listen("tcp", fmt.Sprintf(":%v", *port))
	if err != nil {
		log.Printf("Error: %v\n", utils.ErrorMessage("can't start listen connections", err))
		os.Exit(1)
	}
	if *useTls {
		config.ConnectionWrapper, err = network.NewTLSConnectionWrapper(&tls.Config{InsecureSkipVerify:true})
		if err != nil{
			log.Println("Error: can't initialize tls connection wrapper")
			os.Exit(1)
		}
	} else {
		config.ConnectionWrapper, err = network.NewSecureSessionConnectionWrapper(keyStore)
		if err != nil{
			log.Println("Error: can't initialize secure session connection wrapper")
			os.Exit(1)
		}
	}
	if *withZone {
		go func() {
			// copy config and replace ports
			commandsConfig := *config
			commandsConfig.AcraPort = *acraCommandsPort
			commandsConfig.Port = *commandsPort

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
				go handleClientConnection(&commandsConfig, connection)
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
