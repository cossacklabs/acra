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
	"syscall"
	url_ "net/url"
)

type SServer struct {
	config                *Config
	keystorage            keystore.KeyStore
	listenerACRA          net.Listener
	listenerAPI           net.Listener
	fddACRA               uintptr
	fdAPI                 uintptr
	cmACRA                *network.ConnectionManager
	cmAPI                 *network.ConnectionManager
	listeners             []net.Listener
	errorSignalChannel    chan os.Signal
	restartSignalsChannel chan os.Signal
}

func NewServer(config *Config, keystorage keystore.KeyStore, errorChan chan os.Signal, restarChan chan os.Signal) (server *SServer, err error) {
	return &SServer{
		config:                config,
		keystorage:            keystorage,
		cmACRA:                network.NewConnectionManager(),
		cmAPI:                 network.NewConnectionManager(),
		errorSignalChannel:    errorChan,
		restartSignalsChannel: restarChan,
	}, nil
}

// Close all listeners and return first error
func (server *SServer) Close() {
	log.Debugln("Closing server listeners..")
	var err error
	for _, listener := range server.listeners {
		switch listener.(type) {
		case *net.TCPListener:
			err = listener.(*net.TCPListener).Close()
			if err != nil {
				log.WithError(err).Infoln("TCPListener.Close()")
				continue
			}
		case *net.UnixListener:
			err = listener.(*net.UnixListener).Close()
			if err != nil {
				log.WithError(err).Infoln("UnixListener.Close()")
				continue
			}
			// TODO: find better way to remove unixsocket file
			url, err2 := url_.Parse(server.config.GetAcraConnectionString())
			if err2 != nil {
				log.WithError(err2).Warningln("UnixListener.Close  url_.Parse")
			}
			if _, err := os.Stat(url.Path); err == nil {
				err3 := os.Remove(url.Path)
				if err3 != nil {
					log.WithError(err3).Warningf("UnixListener.Close  file.Remove(%s)", url.Path)
				}
			}
		}
	}
	if err != nil {
		log.WithError(err).Infoln("server.Close()")
	}
	log.Debugln("Closed server listeners")
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
handle new connection by initializing secure session, starting proxy request
to db and decrypting responses from db
*/
func (server *SServer) handleConnection(connection net.Conn) {
	log.Infof("Handle new connection")
	wrappedConnection, clientId, err := server.config.ConnectionWrapper.WrapServer(connection)
	if err != nil {
		log.WithError(err).Println("Can't wrap connection from acraproxy")
		if closeErr := connection.Close(); closeErr != nil {
			log.WithError(closeErr).Println("Can't close connection")
		}
		return
	}
	clientSession, err := NewClientSession(server.keystorage, server.config, connection)
	clientSession.Server = server
	if err != nil {
		log.WithError(err).Println("Can't initialize client session")
		if closeErr := connection.Close(); closeErr != nil {
			log.WithError(closeErr).Println("Can't close connection")
		}
		return
	}
	clientSession.connection = wrappedConnection
	decryptor := server.getDecryptor(clientId)
	clientSession.HandleSecureSession(decryptor)
}

// start listening connections from proxy
func (server *SServer) Start() {
	var connection net.Conn
	var listener, err = network.Listen(server.config.GetAcraConnectionString())
	if err != nil {
		log.WithError(err).Errorln("Can't start listen connections")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}
	server.listenerACRA = listener
	server.addListener(listener)

	log.Infof("Start listening connection: %s", server.config.GetAcraConnectionString())
	for {
		connection, err = listener.Accept()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.Infoln("Stop accepting new connections due net.Timeout")
				return
			}
			log.WithError(err).Errorf("Can't accept new connection (connection=%v)", connection)
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("Got new connection to acraserver: <%v>", connection.LocalAddr())
		} else {
			log.Infof("Got new connection to acraserver: <%v>", connection.RemoteAddr())
		}
		go func() {
			server.cmACRA.Incr()
			server.handleConnection(connection)
			server.cmACRA.Done()
		}()

	}
}

func (server *SServer) StartFromFileDescriptor(fd uintptr) {
	var connection net.Conn
	file := os.NewFile(fd, "/tmp/acraserver")
	listenerFile, err := net.FileListener(file)
	if err != nil {
		log.WithError(err).Errorln("can't start listen for file descriptor")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}

	listenerWithFileDesciptor, ok := listenerFile.(network.ListenerWithFileDescriptor)
	if !ok {
		log.WithError(err).Errorf("File descriptor %d is not a valid socket", fd)
		return
	}
	server.listenerACRA = listenerWithFileDesciptor
	server.addListener(listenerFile)

	log.Infof("Start listening connection: %s", server.config.GetAcraConnectionString())
	for {
		connection, err = listenerWithFileDesciptor.Accept()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.WithError(err).Errorf("stop accepting new connections", connection)
				return
			}
			log.WithError(err).Errorf("can't accept new connection (connection=%v)", connection)
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("Got new connection to acraserver: <%v>", connection.LocalAddr())
		} else {
			log.Infof("Got new connection to acraserver: <%v>", connection.RemoteAddr())
		}
		go func() {
			server.cmACRA.Incr()
			server.handleConnection(connection)
			server.cmACRA.Done()
		}()
	}
}

func (server *SServer) StopListeners() {
	var (
		err         error
		tcpListener *net.TCPListener
		ok          bool
	)
	if tcpListener, ok = server.listenerACRA.(*net.TCPListener); ok {
		err = tcpListener.SetDeadline(time.Now())
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.WithError(err).Errorln("unable to SetDeadLine of acra-listener")
			}
		}
	} else {
		log.Warningln("acra-interface assigment failed")
	}

	if server.listenerAPI != nil {
		if tcpListener, ok = server.listenerAPI.(*net.TCPListener); ok {
			err = tcpListener.SetDeadline(time.Now())
			if err != nil {
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					log.WithError(err).Errorln("unable to SetDeadLine of api-listener")
				}
			}
		} else {
			log.Warningln("API-interface assigment failed")
		}
	}
}

func (server *SServer) WaitConnections(duration time.Duration) {
	log.Infof("Waiting for %v connections to complete", server.ConnectionsCounter())
	server.cmACRA.Wait()
	if server.listenerAPI != nil {
		server.cmAPI.Wait()
	}
}

func (server *SServer) WaitWithTimeout(duration time.Duration) error {
	timeout := time.NewTimer(duration)
	wait := make(chan struct{})
	go func() {
		server.WaitConnections(duration)
		wait <- struct{}{}
	}()

	select {
	case <-timeout.C:
		return ErrWaitTimeout
	case <-wait:
		return nil
	}
}

func (server *SServer) ConnectionsCounter() int {
	return server.cmACRA.Counter + server.cmAPI.Counter
}

/*
handle new connection by initializing secure session, starting proxy request
to db and decrypting responses from db
*/
func (server *SServer) handleCommandsConnection(connection net.Conn) {
	clientSession, err := NewClientCommandsSession(server.keystorage, server.config, connection)
	clientSession.Server = server
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
func (server *SServer) StartCommands() {
	var connection net.Conn
	var listener, err = network.Listen(server.config.GetAcraAPIConnectionString())
	if err != nil {
		log.WithError(err).Errorln("Can't start listen command API connections")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}
	server.listenerAPI = listener
	server.addListener(listener)

	log.Infof("Start listening API: %s", server.config.GetAcraAPIConnectionString())
	for {
		connection, err = listener.Accept()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.WithError(err).Errorf("Stop accepting new connections", connection)
				return
			}
			log.WithError(err).Errorf("Can't accept new connection (connection=%v)", connection)
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("Got new connection to http API: <%v>", connection.LocalAddr())
		} else {
			log.Infof("Got new connection to http API: <%v>", connection.RemoteAddr())
		}
		go func() {
			server.cmAPI.Incr()
			server.handleCommandsConnection(connection)
			server.cmAPI.Done()
		}()
	}
}

func (server *SServer) StartCommandsFromFileDescriptor(fd uintptr) {
	var connection net.Conn
	file := os.NewFile(fd, "/tmp/acraserver_http_api")
	listenerFile, err := net.FileListener(file)
	if err != nil {
		log.WithError(err).Errorln("System error: can't start listen for file descriptor")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}
	listenerWithFileDesciptor, ok := listenerFile.(network.ListenerWithFileDescriptor)
	if !ok {
		log.WithError(err).Errorf("System error: file descriptor %d is not a valid socket", fd)
		return
	}
	server.listenerAPI = listenerWithFileDesciptor
	server.addListener(listenerWithFileDesciptor)

	log.Infof("Start listening API: %s", server.config.GetAcraAPIConnectionString())
	for {
		connection, err = listenerWithFileDesciptor.Accept()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.WithError(err).Errorf("System error: stop accepting new connections", connection)
				return
			}
			log.WithError(err).Errorf("System error: can't accept new connection (connection=%v)", connection)
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("Got new connection to http API: <%v>", connection.LocalAddr())
		} else {
			log.Infof("Got new connection to http API: <%v>", connection.RemoteAddr())
		}
		go func() {
			server.cmAPI.Incr()
			server.handleCommandsConnection(connection)
			server.cmAPI.Done()
		}()
	}
}
