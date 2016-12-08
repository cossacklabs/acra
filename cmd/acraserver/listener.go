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
	. "github.com/cossacklabs/acra/utils"
	"log"
	"net"
	"time"

	"github.com/cossacklabs/acra/config"
	"github.com/cossacklabs/acra/decryptor/base"
	pg "github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/session"
)

const (
	INIT_SSESSION_TIMEOUT = 30 * time.Second
)

type SServer struct {
	config     *config.Config
	keystorage keystore.KeyStore
}

func NewServer(config *config.Config) (server *SServer, err error) {
	keystorage, err := keystore.NewFilesystemKeyStore(config.GetKeysDir())
	if nil == err {
		server = &SServer{config: config, keystorage: keystorage}
	}
	return
}

/*
 initialize SecureSession with new connection
 read client_id, load public key for this client and initialize Secure Session
*/
func (server *SServer) initSSession(connection net.Conn) ([]byte, *ClientSession, error) {
	client_id, err := ReadData(connection)
	if err != nil {
		return nil, nil, err
	}
	private_key, err := server.keystorage.GetServerPrivateKey(client_id)
	if err != nil {
		return nil, nil, err
	}
	client_session, err := NewClientSession(server.keystorage, server.config, connection)
	if err != nil {
		return nil, nil, err
	}
	ssession, err := session.New(server.config.GetServerId(), private_key, client_session)
	if err != nil {
		return nil, nil, err
	}
	client_session.session = ssession
	for {
		data, err := ReadData(connection)
		if err != nil {
			return nil, nil, err
		}
		buf, sendPeer, err := ssession.Unwrap(data)
		if nil != err {
			return nil, nil, err
		}
		if !sendPeer {
			return client_id, client_session, nil
		}

		err = SendData(buf, connection)
		if err != nil {
			return nil, nil, err
		}

		if ssession.GetState() == session.STATE_ESTABLISHED {
			return client_id, client_session, err
		}
	}
}

func (server *SServer) getDecryptor(client_id []byte) base.Decryptor {
	var data_decryptor base.DataDecryptor
	var matcher_pool *zone.MatcherPool
	if server.config.GetByteaFormat() == config.HEX_BYTEA_FORMAT {
		data_decryptor = pg.NewPgHexDecryptor()
		matcher_pool = zone.NewMatcherPool(zone.NewPgHexMatcherFactory())
	} else {
		data_decryptor = pg.NewPgEscapeDecryptor()
		matcher_pool = zone.NewMatcherPool(zone.NewPgEscapeMatcherFactory())
	}
	decryptor_impl := pg.NewPgDecryptor(client_id, data_decryptor)
	decryptor_impl.SetWithZone(server.config.GetWithZone())
	decryptor_impl.SetWholeMatch(server.config.GetWholeMatch())
	decryptor_impl.SetKeyStore(server.keystorage)
	decryptor_impl.SetPoisonKey(server.config.GetPoisonKey())
	zone_matcher := zone.NewZoneMatcher(matcher_pool, server.keystorage)
	decryptor_impl.SetZoneMatcher(zone_matcher)

	poison_callback_storage := base.NewPoisonCallbackStorage()
	if server.config.GetScriptOnPoison() != "" {
		poison_callback_storage.AddCallback(base.NewExecuteScriptCallback(server.config.GetScriptOnPoison()))
	}
	// must be last
	if server.config.GetStopOnPoison() {
		poison_callback_storage.AddCallback(&base.StopCallback{})
	}
	decryptor_impl.SetPoisonCallbackStorage(poison_callback_storage)
	return decryptor_impl
}

/*
handle new connection by iniailizing secure session, starting proxy request
to db and decrypting responses from db
*/
func (server *SServer) handleConnection(connection net.Conn) {
	// initialization of session should be fast, so limit time for connection activity interval
	connection.SetDeadline(time.Now().Add(INIT_SSESSION_TIMEOUT))
	client_id, client_session, err := server.initSSession(connection)
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage("can't initialize secure session with acraproxy", err))
		connection.Close()
		return
	}
	defer client_session.session.Close()
	// reset deadline
	connection.SetDeadline(time.Time{})

	log.Println("Debug: secure session initialized")
	decryptor := server.getDecryptor(client_id)
	client_session.HandleSecureSession(decryptor)
}

// start listening connections from proxy
func (server *SServer) Start() {
	listener, err := net.Listen("tcp", fmt.Sprintf("%v:%v", server.config.GetProxyHost(), server.config.GetProxyPort()))
	if err != nil {
		log.Printf("Error: %v\n", ErrorMessage("can't start listen connections", err))
		return
	}
	log.Printf("Info: start listening %v:%v\n", server.config.GetProxyHost(), server.config.GetProxyPort())
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Printf("Error: %v\n", ErrorMessage(fmt.Sprintf("can't accept new connection (connection=%v)", connection), err))
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
	client_id, err := ReadData(connection)
	if err != nil {
		return nil, err
	}
	private_key, err := server.keystorage.GetServerPrivateKey(client_id)
	if err != nil {
		return nil, err
	}
	client_session, err := NewClientCommandsSession(server.keystorage, server.config, connection)
	if err != nil {
		return nil, err
	}
	ssession, err := session.New(server.config.GetServerId(), private_key, client_session)
	if err != nil {
		return nil, err
	}
	client_session.session = ssession
	if err != nil {
		return nil, err
	}
	for {
		data, err := ReadData(connection)
		if err != nil {
			return nil, err
		}
		buf, sendPeer, err := ssession.Unwrap(data)
		if nil != err {
			return nil, err
		}
		if !sendPeer {
			return client_session, nil
		}

		err = SendData(buf, connection)
		if err != nil {
			return nil, err
		}

		if ssession.GetState() == session.STATE_ESTABLISHED {
			return client_session, err
		}
	}
}

/*
handle new connection by iniailizing secure session, starting proxy request
to db and decrypting responses from db
*/
func (server *SServer) handleCommandsConnection(connection net.Conn) {
	// initialization of session should be fast, so limit time for connection activity interval
	connection.SetDeadline(time.Now().Add(INIT_SSESSION_TIMEOUT))
	client_session, err := server.initCommandsSSession(connection)
	if err != nil {
		log.Println("Error: ", err)
		return
	}
	defer client_session.session.Close()
	// reset deadline
	connection.SetDeadline(time.Time{})
	log.Println("Debug: http api secure session initialized")
	client_session.HandleSession()
}

// start listening commands connections from proxy
func (server *SServer) StartCommands() {
	listener, err := net.Listen("tcp", fmt.Sprintf("%v:%v", server.config.GetProxyHost(), server.config.GetProxyCommandsPort()))
	if err != nil {
		return
	}
	log.Printf("Info: start listening %v:%v\n", server.config.GetProxyHost(), server.config.GetProxyCommandsPort())
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Printf("Error: %v\n", ErrorMessage(fmt.Sprintf("can't accept new connection (%v)", connection.RemoteAddr()), err))
			continue
		}
		log.Printf("Info: new connection to http api: %v\n", connection.RemoteAddr())
		go server.handleCommandsConnection(connection)
	}
}
