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
	url_ "net/url"
	"os"
	"syscall"
	"time"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/mysql"
	pg "github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/zone"
	log "github.com/sirupsen/logrus"
)

// SServer represents AcraServer server, connects with KeyStorage, configuration file,
// data and command connections (listeners, managers, file descriptors), and signals.
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

// NewServer creates new SServer.
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
	pgDecryptorImpl := pg.NewPgDecryptor(clientId, dataDecryptor)
	pgDecryptorImpl.SetWithZone(server.config.GetWithZone())
	pgDecryptorImpl.SetWholeMatch(server.config.GetWholeMatch())
	pgDecryptorImpl.SetKeyStore(server.keystorage)
	zoneMatcher := zone.NewZoneMatcher(matcherPool, server.keystorage)
	pgDecryptorImpl.SetZoneMatcher(zoneMatcher)

	poisonCallbackStorage := base.NewPoisonCallbackStorage()
	if server.config.GetScriptOnPoison() != "" {
		poisonCallbackStorage.AddCallback(base.NewExecuteScriptCallback(server.config.GetScriptOnPoison()))
	}
	// must be last
	if server.config.GetStopOnPoison() {
		poisonCallbackStorage.AddCallback(&base.StopCallback{})
	}
	pgDecryptorImpl.SetPoisonCallbackStorage(poisonCallbackStorage)
	var decryptor base.Decryptor = pgDecryptorImpl
	if server.config.UseMySQL() {
		decryptor = mysql.NewMySQLDecryptor(clientId, pgDecryptorImpl, server.keystorage)
	}
	decryptor.TurnOnPoisonRecordCheck(server.config.DetectPoisonRecords())
	return decryptor
}

/*
handle new connection by initializing secure session, starting proxy request
to db and decrypting responses from db
*/
func (server *SServer) handleConnection(connection net.Conn) {
	log.Infof("Handle new connection")
	wrappedConnection, clientId, err := server.config.ConnectionWrapper.WrapServer(connection)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantWrapConnection).
			Errorln("Can't wrap connection from acra-connector")
		if closeErr := connection.Close(); closeErr != nil {
			log.WithError(closeErr).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnection).
				Errorln("Can't close connection")
		}
		return
	}
	clientSession, err := NewClientSession(server.keystorage, server.config, connection)
	clientSession.Server = server
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitClientSession).
			Errorln("Can't initialize client session")
		if closeErr := wrappedConnection.Close(); closeErr != nil {
			log.WithError(closeErr).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnection).
				Errorln("Can't close connection")
		}
		return
	}
	clientSession.connection = wrappedConnection
	decryptor := server.getDecryptor(clientId)
	clientSession.HandleClientConnection(clientId, decryptor)
}

// Start listening connections from proxy
func (server *SServer) Start() {
	var connection net.Conn
	var listener, err = network.Listen(server.config.GetAcraConnectionString())
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartListenConnections).
			Errorln("Can't start listen connections")
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
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorConnectionDroppedByTimeout).
					Errorln("Stop accepting new connections due net.Timeout")
				return
			}
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantAcceptNewConnections).
				Errorf("Can't accept new connection (connection=%v)", connection)
			continue
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("Got new connection to AcraServer: %v", connection.LocalAddr())
		} else {
			log.Infof("Got new connection to AcraServer: %v", connection.RemoteAddr())
		}
		go func() {
			server.cmACRA.Incr()
			server.handleConnection(connection)
			server.cmACRA.Done()
		}()

	}
}

// StartFromFileDescriptor starts listening Acra data connections from file descriptor.
func (server *SServer) StartFromFileDescriptor(fd uintptr) {
	file := os.NewFile(fd, "/tmp/acra-server")
	if file == nil {
		log.Errorln("Can't create new file from descriptor for acra listener")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}
	listenerFile, err := net.FileListener(file)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantOpenFileByDescriptor).
			Errorln("System error: can't start listen for file descriptor")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}

	listenerWithFileDescriptor, ok := listenerFile.(network.ListenerWithFileDescriptor)
	if !ok {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorFileDescriptionIsNotValid).
			Errorf("System error: file descriptor %d is not a valid socket", fd)
		return
	}
	server.listenerACRA = listenerWithFileDescriptor
	server.addListener(listenerFile)

	log.Infof("Start listening connection: %s", server.config.GetAcraConnectionString())
	for {
		connection, err := listenerWithFileDescriptor.Accept()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorConnectionDroppedByTimeout).
					Errorf("Stop accepting new connections")
				return
			}
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantAcceptNewConnections).
				Errorf("Can't accept new connection")
			continue
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("Got new connection to AcraServer: %v", connection.LocalAddr())
		} else {
			log.Infof("Got new connection to AcraServer: %v", connection.RemoteAddr())
		}
		go func() {
			server.cmACRA.Incr()
			server.handleConnection(connection)
			server.cmACRA.Done()
		}()
	}
}

// stopAcceptConnections stop accepting by setting deadline and then background code that call Accept will took error and
// stop execution
func stopAcceptConnections(listener network.DeadlineListener) (err error) {
	if listener != nil {
		err = listener.SetDeadline(time.Now())
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStopListenConnections).
					Errorln("Unable to SetDeadLine for listener")
			} else {
				log.WithError(err).Errorln("Non-timeout error")
			}
		}
	} else {
		log.Warningln("can't set deadline for server listener")
	}
	return
}

// StopListeners stops accepts new connections, and stops existing listeners with deadline.
func (server *SServer) StopListeners() {
	var err error
	var deadlineListener network.DeadlineListener
	log.Debugln("Stopping listeners")

	for _, listener := range server.listeners {

		deadlineListener, err = network.CastListenerToDeadline(listener)
		if err != nil {
			log.WithError(err).Warningln("Can't cast listener")
			continue
		}

		if err = stopAcceptConnections(deadlineListener); err != nil {
			log.WithError(err).Warningln("Can't set deadline for listener")
		}
	}
}

// WaitConnections waits until connection complete or stops them after duration time.
func (server *SServer) WaitConnections(duration time.Duration) {
	log.Infof("Waiting for %v connections to complete", server.ConnectionsCounter())
	server.cmACRA.Wait()
	if server.listenerAPI != nil {
		server.cmAPI.Wait()
	}
}

// WaitWithTimeout waits until connection complete or stops them after duration time.
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

// ConnectionsCounter counts number of active data and API connections.
func (server *SServer) ConnectionsCounter() int {
	return server.cmACRA.Counter + server.cmAPI.Counter
}

/*
handle new connection by initializing secure session, starting proxy request
to db and decrypting responses from db
*/
func (server *SServer) handleCommandsConnection(connection net.Conn) {
	log.Infof("Handle commands connection")
	clientSession, err := NewClientCommandsSession(server.keystorage, server.config, connection)
	clientSession.Server = server
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
			Errorln("Can't init API session")
		return
	}

	wrappedConnection, _, err := server.config.ConnectionWrapper.WrapServer(connection)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantWrapConnection).
			Errorln("Can't wrap API connection")
		return
	}
	clientSession.connection = wrappedConnection
	clientSession.HandleSession()
}

// StartCommands starts listening commands connections from proxy.
func (server *SServer) StartCommands() {
	var connection net.Conn
	var listener, err = network.Listen(server.config.GetAcraAPIConnectionString())
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartListenConnections).
			Errorln("Can't start listen command API connections")
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
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantAcceptNewConnections).
					Errorln("Stop accepting new connections", connection)
				return
			}
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantAcceptNewConnections).
				Errorf("Can't accept new connection (connection=%v)", connection)
			continue
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("Got new connection to http API: %v", connection.LocalAddr())
		} else {
			log.Infof("Got new connection to http API: %v", connection.RemoteAddr())
		}
		go func() {
			server.cmAPI.Incr()
			server.handleCommandsConnection(connection)
			server.cmAPI.Done()
		}()
	}
}

// StartCommandsFromFileDescriptor starts listening commands connections from file descriptor.
func (server *SServer) StartCommandsFromFileDescriptor(fd uintptr) {
	var connection net.Conn
	file := os.NewFile(fd, "/tmp/acra-server_http_api")
	if file == nil {
		log.Errorln("Can't create new file from descriptor for api listener")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}
	listenerFile, err := net.FileListener(file)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantOpenFileByDescriptor).
			Errorln("System error: can't start listen for file descriptor")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}
	listenerWithFileDescriptor, ok := listenerFile.(network.ListenerWithFileDescriptor)
	if !ok {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorFileDescriptionIsNotValid).
			Errorf("System error: file descriptor %d is not a valid socket", fd)
		return
	}
	server.listenerAPI = listenerWithFileDescriptor
	server.addListener(listenerWithFileDescriptor)

	log.Infof("Start listening API from file descriptor: %s", server.config.GetAcraAPIConnectionString())
	for {
		connection, err = listenerWithFileDescriptor.Accept()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorConnectionDroppedByTimeout).
					Errorln("Stop accepting new connections", connection)
				return
			}
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantAcceptNewConnections).
				Errorf("System error: can't accept new connection (connection=%v)", connection)
			continue
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("Got new connection to http API: %v", connection.LocalAddr())
		} else {
			log.Infof("Got new connection to http API: %v", connection.RemoteAddr())
		}
		go func() {
			server.cmAPI.Incr()
			server.handleCommandsConnection(connection)
			server.cmAPI.Done()
		}()
	}
}
