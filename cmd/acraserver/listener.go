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
	"syscall"
	url_ "net/url"
)

type SServer struct {
	config       *Config
	keystorage   keystore.KeyStore
	listenerACRA net.Listener
	listenerAPI  net.Listener
	fddACRA      uintptr
	fdAPI        uintptr
	cmACRA       *network.ConnectionManager
	cmAPI        *network.ConnectionManager
	listeners    []net.Listener
}

func NewServer(config *Config, keystorage keystore.KeyStore) (server *SServer, err error) {
	return &SServer{
		config:     config,
		keystorage: keystorage,
		cmACRA:     network.NewConnectionManager(),
		cmAPI:      network.NewConnectionManager(),
	}, nil
}

// Close all listeners and return first error
func (server *SServer) Close() {
	log.Debugln("Closing listeners")
	var err error
	for _, listener := range server.listeners {
		switch listener.(type) {
		case *net.TCPListener:
			listener.(*net.TCPListener).Close()
		case *net.UnixListener:
			err = listener.(*net.UnixListener).Close()
			if err != nil {
				log.WithError(err).Infoln("UnixListener.Close()")
				continue
			}
			// TODO: find better way to remove unixsocket file
			f, err1 :=listener.(*net.UnixListener).File()
			_ = f
			if err1 != nil {
				log.WithError(err).Warningln("UnixListener.Close File()")
			}
			url, err2 := url_.Parse(server.config.GetAcraConnectionString())
			if err2 != nil {
				log.WithError(err).Warningln("UnixListener.Close  url_.Parse")
			}
			err3 := os.Remove(url.Path)
			if err3 != nil {
				log.WithError(err).Warningf("UnixListener.Close  file.Remove(%s)", url.Path)
			}
		}
	}
	if err != nil {
		log.WithError(err).Infoln("server.Close()")
	}
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
func (server *SServer) Start() {
	var connection net.Conn
	var listener, err = network.Listen(server.config.GetAcraConnectionString())
	if err != nil {
		log.WithError(err).Errorln("can't start listen connections")
		ErrorSignalChannel <- syscall.SIGTERM
		return
	}
	server.listenerACRA = listener
	server.addListener(listener)

	log.Infof("start listening %s", server.config.GetAcraConnectionString())
	for {
		connection, err = listener.Accept()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.Infoln("stop accepting new connections due net.Timeout")
				return
			}
			log.WithError(err).Errorf("can't accept new connection (connection=%v)", connection)
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("new connection to acraserver: <%v>", connection.LocalAddr())
		} else {
			log.Infof("new connection to acraserver: <%v>", connection.RemoteAddr())
		}
		go func() {
			server.cmACRA.Add(1)
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
		ErrorSignalChannel <- syscall.SIGTERM
		return
	}

	listenerWithFileDesciptor, ok := listenerFile.(network.ListenerWithFileDescriptor)
	if !ok {
		log.WithError(err).Errorf("File descriptor %d is not a valid socket", fd)
		return
	}
	server.listenerACRA = listenerWithFileDesciptor
	server.addListener(listenerFile)

	log.Infof("start listening %s", server.config.GetAcraConnectionString())
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
			log.Infof("new connection to acraserver: <%v>", connection.LocalAddr())
		} else {
			log.Infof("new connection to acraserver: <%v>", connection.RemoteAddr())
		}
		go func() {
			server.cmACRA.Add(1)
			server.handleConnection(connection)
			server.cmACRA.Done()
		}()
	}
}

func (server *SServer) StopListeners() {
	var (
		err  error
		nerr *net.TCPListener
		ok   bool
	)
	if nerr, ok = server.listenerACRA.(*net.TCPListener); ok {
		err = server.listenerACRA.(*net.TCPListener).SetDeadline(time.Now())
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.WithError(err).Errorln("unable to SetDeadLine of acra-listener")
			}
		}
	}
	if nerr != nil {
		log.Warningf("acra-interface assigment failed - %v", nerr)
	}

	if server.listenerAPI != nil {
		if nerr, ok = server.listenerAPI.(*net.TCPListener); ok {
			err = server.listenerAPI.(*net.TCPListener).SetDeadline(time.Now())
			if err != nil {
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					log.WithError(err).Errorln("unable to SetDeadLine of api-listener")
				}
			}
		} else {
			log.Warningf("api-interface assigment failed - %v", nerr)
		}
	}
}

func (server *SServer) WaitConnections(duration time.Duration) {
	log.Infof("waiting for %v connections to complete", server.ConnectionsCounter())
	server.cmACRA.Wait()
	if server.listenerAPI != nil {
		server.cmAPI.Wait()
	}
}

var WaitTimeoutError = errors.New("timeout")

func (server *SServer) WaitWithTimeout(duration time.Duration) error {
	timeout := time.NewTimer(duration)
	wait := make(chan struct{})
	go func() {
		server.WaitConnections(duration)
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
func (server *SServer) StartCommands() {
	var connection net.Conn
	var listener, err = network.Listen(server.config.GetAcraAPIConnectionString())
	if err != nil {
		log.WithError(err).Errorln("can't start listen command api connections")
		ErrorSignalChannel <- syscall.SIGTERM
		return
	}
	server.listenerAPI = listener
	server.addListener(listener)

	log.Infof("start listening api %s", server.config.GetAcraAPIConnectionString())
	for {
		connection, err = listener.Accept()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.WithError(err).Errorf("stop accepting new connections", connection)
				return
			}
			log.WithError(err).Errorf("can't accept new connection (connection=%v)", connection)
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			log.Infof("new connection to http api: <%v>", connection.LocalAddr())
		} else {
			log.Infof("new connection to http api: <%v>", connection.RemoteAddr())
		}
		go func() {
			server.cmAPI.Add(1)
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
		log.WithError(err).Errorln("can't start listen for file descriptor")
		ErrorSignalChannel <- syscall.SIGTERM
		return
	}
	listenerWithFileDesciptor, ok := listenerFile.(network.ListenerWithFileDescriptor)
	if !ok {
		log.WithError(err).Errorf("File descriptor %d is not a valid socket", fd)
		return
	}
	server.listenerAPI = listenerWithFileDesciptor
	server.addListener(listenerWithFileDesciptor)

	log.Infof("start listening api %s", server.config.GetAcraAPIConnectionString())
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
			log.Infof("new connection to http api: <%v>", connection.LocalAddr())
		} else {
			log.Infof("new connection to http api: <%v>", connection.RemoteAddr())
		}
		go func() {
			server.cmAPI.Add(1)
			server.handleCommandsConnection(connection)
			server.cmAPI.Done()
		}()
	}
}
