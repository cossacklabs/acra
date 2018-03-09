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
	"net"

	"github.com/cossacklabs/acra/network"
	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/decryptor/base"
	pg "github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/zone"
	"os"
	"time"
	"errors"
	"fmt"
)

type SServer struct {
	config     *Config
	keystorage keystore.KeyStore
	socketACRA *net.TCPListener
	socketAPI  *net.TCPListener
	fdACRA     uintptr
	fdAPI      uintptr
	cmACRA     *network.ConnectionManager
	cmAPI      *network.ConnectionManager
	listeners  []net.Listener
}

func NewServer(config *Config, keystorage keystore.KeyStore) (server *SServer, err error) {
	return &SServer{
		config:     config,
		keystorage: keystorage,
		cmACRA:     network.NewConnectionManager(),
		cmAPI:      network.NewConnectionManager(),
	}, nil
}

func NewFromFD(config *Config, keystorage keystore.KeyStore, fdACRA uintptr, fdAPI uintptr) (server *SServer, err error) {
	return &SServer{
		config:     config,
		keystorage: keystorage,
		cmACRA:     network.NewConnectionManager(),
		cmAPI:      network.NewConnectionManager(),
		fdACRA:     fdACRA,
		fdAPI:      fdAPI,
	}, nil

}

// Close all listeners and return first error
func (server *SServer) Close() error {
	var err error
	for _, listener := range server.listeners {
		if err_ := listener.Close(); err_ != nil && err == nil {
			err = err_
		}
	}
	return err
}

func (server *SServer) addListener(listener net.Listener) {
	server.listeners = append(server.listeners, listener)
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
	decryptor := server.getDecryptor(clientId)
	clientSession.HandleSecureSession(decryptor)
}

// start listening connections from proxy
func (server *SServer) Start(graceful bool) {
	var listener net.Listener
	var listenerGraceful *net.TCPListener
	var err error
	var connection net.Conn
	if graceful == true {
		listenerGraceful, err = network.ListenTCP(server.config.GetAcraConnectionString())
		if err != nil {
			log.WithError(err).Errorln("can't start listen connections")
			return
		}
		server.socketACRA = listenerGraceful
		defer listenerGraceful.Close()
	} else {
		listener, err = network.Listen(server.config.GetAcraConnectionString())
		if err != nil {
			log.WithError(err).Errorln("can't start listen connections")
			return
		}
		defer listener.Close()
	}

	log.Infof("start listening %s", server.config.GetAcraConnectionString())
	for {
		if graceful == true {
			connection, err = listenerGraceful.Accept()
		} else {
			connection, err = listener.Accept()
		}
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

func (server *SServer) StartFromFileDescriptor(fd uintptr) {
	file := os.NewFile(fd, fmt.Sprintf("/tmp/acraserver_%v", os.Getpid()))
	listener, err := net.FileListener(file)
	if err != nil {
		log.WithError(err).Errorln("can't start listen for file descriptor")
		return
	}
	listenerTCP, ok := listener.(*net.TCPListener)
	if !ok {
		log.WithError(err).Errorf("File descriptor %d is not a valid TCP socket", fd)
		return
	}
	server.socketACRA = listenerTCP
	defer listener.Close()
	server.addListener(listener)
	log.Infof("start listening %s", server.config.GetAcraConnectionString())
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.WithError(err).Errorln("can't accept new connection")
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

func (server *SServer) Stop(socket *net.TCPListener) {
	socket.SetDeadline(time.Now())
}

func (server *SServer) ListenerFD(socket *net.TCPListener) (uintptr, error) {
	file, err := socket.File()
	if err != nil {
		return 0, err
	}
	return file.Fd(), nil
}

func (server *SServer) WaitAPI() {
	server.cmAPI.Wait()
}
func (server *SServer) WaitACRA() {
	server.cmACRA.Wait()
}

var WaitTimeoutError = errors.New("timeout")

func (server *SServer) WaitWithTimeout(duration time.Duration) error {
	timeout := time.NewTimer(duration)
	wait := make(chan struct{})
	go func() {
		server.WaitACRA()
		if server.config.GetWithZone() && server.config.GetEnableHTTPApi() {
			server.Stop(server.socketAPI)
		}
		wait <- struct{}{}
	}()

	select {
	case <-timeout.C:
		return WaitTimeoutError
	case <-wait:
		return nil
	}
}

func (server *SServer) Addr(socket *net.TCPListener) net.Addr {
	return socket.Addr()
}

func (server *SServer) ConnectionsCounter() int {
	return server.cmACRA.Counter + server.cmAPI.Counter
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
	clientSession.HandleSession()
}

// start listening commands connections from proxy
func (server *SServer) StartCommands(graceful bool) {
	var listener net.Listener
	var listenerGraceful *net.TCPListener
	var err error
	var connection net.Conn
	if graceful == true {
		listenerGraceful, err = network.ListenTCP(server.config.GetAcraAPIConnectionString())
		if err != nil {
			log.WithError(err).Errorln("can't start listen command api connections")
			return
		}
		server.socketAPI = listenerGraceful
	} else {
		listener, err = network.Listen(server.config.GetAcraAPIConnectionString())
		if err != nil {
			log.WithError(err).Errorln("can't start listen command api connections")
			return
		}
	}
	log.Infof("start listening api %s", server.config.GetAcraAPIConnectionString())
	for {
		if graceful == true {
			connection, err = listenerGraceful.Accept()
		} else {
			connection, err = listener.Accept()
		}

		if err != nil {
			// log.WithError(err).Errorf("can't accept new connection (%v)", connection.RemoteAddr())
			log.WithError(err).Errorf("can't accept new connection")
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

func (server *SServer) StartCommandsFromFileDescriptor(fd uintptr) {
	file := os.NewFile(fd, fmt.Sprintf("/tmp/acraserver_http_api_%v", os.Getpid()))
	listener, err := net.FileListener(file)
	if err != nil {
		log.WithError(err).Errorln("can't start listen for file descriptor")
		return
	}
	listenerTCP, ok := listener.(*net.TCPListener)
	if !ok {
		log.WithError(err).Errorf("File descriptor %d is not a valid TCP socket", fd)
		return
	}
	server.socketAPI = listenerTCP
	defer listener.Close()
	server.addListener(listener)
	log.Infof("start listening api %s", server.config.GetAcraAPIConnectionString())
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.WithError(err).Errorln("can't accept new connection")
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
