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
	"github.com/cossacklabs/acra/network"
	log "github.com/sirupsen/logrus"
	"net"

	"github.com/cossacklabs/acra/decryptor/base"
	pg "github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/zone"
)

type SServer struct {
	config     *Config
	keystorage keystore.KeyStore
}

func NewServer(config *Config, keystorage keystore.KeyStore) (server *SServer, err error) {
	return &SServer{config: config, keystorage: keystorage}, nil
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
	wrappedConnection, clientId, err := server.config.ConnectionWrapper.WrapServer(connection)
	if err != nil {
		log.WithError(err).Println("can't wrap connection from acraproxy")
		if closeErr := connection.Close(); closeErr != nil {
			log.WithError(closeErr).Println("can't close connection")
		}
		return
	}
	clientSession, err := NewClientSession(server.keystorage, server.config, connection)
	if err != nil {
		log.WithError(err).Println("can't initialize client session")
		if closeErr := connection.Close(); closeErr != nil {
			log.WithError(closeErr).Println("can't close connection")
		}
		return
	}
	clientSession.connection = wrappedConnection

	log.Debugln("secure session initialized")
	decryptor := server.getDecryptor(clientId)
	clientSession.HandleSecureSession(decryptor)
}

// start listening connections from proxy
func (server *SServer) Start() {
	listener, err := network.Listen(server.config.GetAcraConnectionString())
	if err != nil {
		log.WithError(err).Errorln("can't start listen connections")
		return
	}
	defer listener.Close()
	log.Infof("start listening %s", server.config.GetAcraConnectionString())
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.WithError(err).Errorf("can't accept new connection (connection=%v)", connection)
			continue
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("new connection to acraserver: <%v>", connection.LocalAddr())
		} else {
			log.Infof("new connection to acraserver: <%v>", connection.RemoteAddr())
		}
		go server.handleConnection(connection)
	}
}

/*
handle new connection by iniailizing secure session, starting proxy request
to db and decrypting responses from db
*/
func (server *SServer) handleCommandsConnection(connection net.Conn) {
	clientSession, err := NewClientCommandsSession(server.keystorage, server.config, connection)
	if err != nil {
		log.WithError(err).Errorln("can't init session")
		return
	}

	wrappedConnection, _, err := server.config.ConnectionWrapper.WrapServer(connection)
	if err != nil {
		log.WithError(err).Errorln("can't wrap connection")
		return
	}
	clientSession.connection = wrappedConnection
	log.Debugln("http api secure session initialized")
	clientSession.HandleSession()
}

// start listening commands connections from proxy
func (server *SServer) StartCommands() {
	listener, err := network.Listen(server.config.GetAcraAPIConnectionString())
	if err != nil {
		log.WithError(err).Errorln("can't start listen command connections")
		return
	}
	log.Infof("start listening api %s", server.config.GetAcraAPIConnectionString())
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.WithError(err).Errorf("can't accept new connection (%v)", connection.RemoteAddr())
			continue
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("new connection to http api: <%v>", connection.LocalAddr())
		} else {
			log.Infof("new connection to http api: <%v>", connection.RemoteAddr())
		}
		go server.handleCommandsConnection(connection)
	}
}
