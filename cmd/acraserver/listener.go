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
	"fmt"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
	"net"
	"time"

	"github.com/cossacklabs/acra/decryptor/base"
	pg "github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/zone"
)

const (
	INIT_SSESSION_TIMEOUT = 30 * time.Second
)

type SServer struct {
	config     *Config
	keystorage keystore.KeyStore
}

func NewServer(config *Config) (server *SServer, err error) {
	keystorage, err := keystore.NewFilesystemKeyStore(config.GetKeysDir())
	if nil == err {
		server = &SServer{config: config, keystorage: keystorage}
	}
	return
}

func (server *SServer) getDecryptor(clientId []byte) base.Decryptor {
	var dataDecryptor base.DataDecryptor
	var matcherPool *zone.MatcherPool
	if server.config.GetByteaFormat() == HEX_BYTEA_FORMAT {
		dataDecryptor = pg.NewPgHexDecryptor()
		matcherPool = zone.NewMatcherPool(zone.NewPgHexMatcherFactory())
	} else {
		dataDecryptor = pg.NewPgEscapeDecryptor()
		matcherPool = zone.NewMatcherPool(zone.NewPgEscapeMatcherFactory())
	}
	decryptorImpl := pg.NewPgDecryptor(clientId, dataDecryptor)
	decryptorImpl.SetWithZone(server.config.GetWithZone())
	decryptorImpl.SetWholeMatch(server.config.GetWholeMatch())
	decryptorImpl.SetKeyStore(server.keystorage)
	zoneMatcher := zone.NewZoneMatcher(matcherPool, server.keystorage)
	decryptorImpl.SetZoneMatcher(zoneMatcher)

	poisonCallbackStorage := base.NewPoisonCallbackStorage()
	if server.config.GetScriptOnPoison() != "" {
		poisonCallbackStorage.AddCallback(base.NewExecuteScriptCallback(server.config.GetScriptOnPoison()))
	}
	// must be last
	if server.config.GetStopOnPoison() {
		poisonCallbackStorage.AddCallback(&base.StopCallback{})
	}
	decryptorImpl.SetPoisonCallbackStorage(poisonCallbackStorage)
	return decryptorImpl
}

/*
handle new connection by iniailizing secure session, starting proxy request
to db and decrypting responses from db
*/
func (server *SServer) handleConnection(connection net.Conn) {
	// initialization of session should be fast, so limit time for connection activity interval
	connection.SetDeadline(time.Now().Add(INIT_SSESSION_TIMEOUT))
	wrappedConnection, clientId, err := server.config.ConnectionWrapper.WrapServer(connection)
	if err != nil{
		log.WithError(err).Println("can't wrap connection from acraproxy")
		if closeErr := connection.Close(); closeErr != nil{
			log.WithError(closeErr).Println("can't close connection")
		}
		return
	}
	// reset deadline
	connection.SetDeadline(time.Time{})

	clientSession, err := NewClientSession(server.keystorage, server.config, connection)
	if err != nil {
		log.WithError(err).Println("Error: can't initialize client session")
		if closeErr := connection.Close(); closeErr != nil {
			log.WithError(closeErr).Println("Error: can't close connection")
		}
		return
	}
	clientSession.connection = wrappedConnection

	log.Println("Debug: secure session initialized")
	decryptor := server.getDecryptor(clientId)
	clientSession.HandleSecureSession(decryptor)
}

// start listening connections from proxy
func (server *SServer) Start() {
	listener, err := net.Listen("tcp", fmt.Sprintf("%v:%v", server.config.GetProxyHost(), server.config.GetProxyPort()))
	if err != nil {
		log.Printf("Error: %v\n", utils.ErrorMessage("can't start listen connections", err))
		return
	}
	log.Printf("Info: start listening %v:%v\n", server.config.GetProxyHost(), server.config.GetProxyPort())
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Printf("Error: %v\n", utils.ErrorMessage(fmt.Sprintf("can't accept new connection (connection=%v)", connection), err))
			continue
		}
		log.Printf("Info: new connection: %v\n", connection.RemoteAddr())
		go server.handleConnection(connection)
	}
}

/*
 initialize SecureSession with new connection
 read client_id, load public key for this client and initialize Secure Session
*/
func (server *SServer) initCommandsSSession(connection net.Conn) (*ClientCommandsSession, error) {
	return NewClientCommandsSession(server.keystorage, server.config, connection)
}

/*
handle new connection by iniailizing secure session, starting proxy request
to db and decrypting responses from db
*/
func (server *SServer) handleCommandsConnection(connection net.Conn) {
	// initialization of session should be fast, so limit time for connection activity interval
	connection.SetDeadline(time.Now().Add(INIT_SSESSION_TIMEOUT))
	clientSession, err := server.initCommandsSSession(connection)
	if err != nil {
		log.Println("Error: ", err)
		return
	}
	defer clientSession.session.Close()
	
	wrappedConnection, _, err := server.config.ConnectionWrapper.WrapServer(connection)
	if err != nil{
		return
	}
	clientSession.connection = wrappedConnection
	// reset deadline
	connection.SetDeadline(time.Time{})
	log.Println("Debug: http api secure session initialized")
	clientSession.HandleSession()
}

// start listening commands connections from proxy
func (server *SServer) StartCommands() {
	log.Printf("Info: start listening http api %v\n", server.config.GetProxyCommandsPort())
	listener, err := net.Listen("tcp", fmt.Sprintf("%v:%v", server.config.GetProxyHost(), server.config.GetProxyCommandsPort()))
	if err != nil {
		log.Printf("Error: %v\n", utils.ErrorMessage("can't start listen command connections", err))
		return
	}
	log.Printf("Info: start listening %v:%v\n", server.config.GetProxyHost(), server.config.GetProxyCommandsPort())
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Printf("Error: %v\n", utils.ErrorMessage(fmt.Sprintf("can't accept new connection (%v)", connection.RemoteAddr()), err))
			continue
		}
		log.Printf("Info: new connection to http api: %v\n", connection.RemoteAddr())
		go server.handleCommandsConnection(connection)
	}
}
