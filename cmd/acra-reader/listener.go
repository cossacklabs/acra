// Copyright 2018, Cossack Labs Limited
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
	"os"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/network"
	log "github.com/sirupsen/logrus"
	"github.com/cossacklabs/acra/logging"
	"syscall"
	"time"
)

type ReaderServer struct {
	config                *AcraReaderConfig
	keystorage            keystore.KeyStore
	listenerHTTP          net.Listener
	listenerGRPC          net.Listener
	cmHTTP                *network.ConnectionManager
	cmGRPC                *network.ConnectionManager
	listeners             []net.Listener
	errorSignalChannel    chan os.Signal
}

func NewReaderServer(config *AcraReaderConfig, keystorage keystore.KeyStore, errorChan chan os.Signal) (server *ReaderServer, err error) {
	return &ReaderServer{
		config:             config,
		keystorage:         keystorage,
		cmHTTP:             network.NewConnectionManager(),
		cmGRPC:             network.NewConnectionManager(),
		errorSignalChannel: errorChan,
	}, nil
}

func (server *ReaderServer) Start() {
	// WARNING: not implemented yet
	// TODO: implement the same for gRPC connection

	var connection net.Conn
	var listener, err = network.Listen(server.config.IncomingConnectionHTTPString())
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartListenConnections).
			Errorln("Can't start listen connections")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}
	server.listenerHTTP = listener
	server.addListener(listener)

	log.Infof("Start listening connection: %s", server.config.IncomingConnectionHTTPString())
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
			log.Infof("Got new connection to AcraReader: %v", connection.LocalAddr())
		} else {
			log.Infof("Got new connection to AcraReader: %v", connection.RemoteAddr())
		}
		go func() {
			server.cmHTTP.Incr()
			server.handleConnection(connection)
			server.cmHTTP.Done()
		}()

	}
}

func (server *ReaderServer) addListener(listener net.Listener) {
	server.listeners = append(server.listeners, listener)
}

func (server *ReaderServer) Close() {
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
		}
	}
	if err != nil {
		log.WithError(err).Infoln("server.Close()")
	}
	log.Debugln("Closed server listeners")
}


func (server *ReaderServer) WaitWithTimeout(duration time.Duration) error {
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

func (server *ReaderServer) WaitConnections(duration time.Duration) {
	log.Infof("Waiting for %v connections to complete", server.ConnectionsCounter())

	if server.listenerHTTP != nil {
		server.cmHTTP.Wait()
	}
	if server.listenerGRPC != nil {
		server.cmGRPC.Wait()
	}
}

func (server *ReaderServer) ConnectionsCounter() int {
	return server.cmGRPC.Counter + server.cmHTTP.Counter
}

// TODO: similar to AcraServer. How to refactor?

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

func (server *ReaderServer) StopListeners() {
	var err error
	var listener network.DeadlineListener
	log.Debugln("Stopping listeners")

	switch server.listenerGRPC.(type) {
	case *net.TCPListener:
		listener = server.listenerGRPC.(*net.TCPListener)
	case nil:
		log.Debugln("hasn't GRPC listener")
	default:
		log.Warningln("unsupported listener")
	}

	if err = stopAcceptConnections(listener); err != nil {
		log.WithError(err).Warningln("Can't set deadline for GRPC listener")
	}

	switch server.listenerHTTP.(type) {
	case *net.TCPListener:
		listener = server.listenerHTTP.(*net.TCPListener)
	case nil:
		log.Debugln("hasn't HTTP listener")
	default:
		log.Warningln("unsupported listener")
	}
	if err = stopAcceptConnections(listener); err != nil {
		log.WithError(err).Warningln("Can't set deadline for HTTP listener")
	}

}

/*
handle new connection by initializing secure session, starting proxy request
to db and decrypting responses from db
*/
func (server *ReaderServer) handleConnection(connection net.Conn) {
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

	// WARNING: not implemented yet
	// TODO: start client session
	log.Infof("Not implemented yet: should start client session with %s, clientId=%s", wrappedConnection, clientId)
}
