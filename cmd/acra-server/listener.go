/*
Copyright 2016, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"go.opencensus.io/trace"
	"net"
	url_ "net/url"
	"os"
	"syscall"
	"time"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

// SServer represents AcraServer server, connects with KeyStorage, configuration file,
// data and command connections (listeners, managers, file descriptors), and signals.
type SServer struct {
	config                *Config
	listenerACRA          net.Listener
	listenerAPI           net.Listener
	fddACRA               uintptr
	fdAPI                 uintptr
	connectionManager     *network.ConnectionManager
	listeners             []net.Listener
	errorSignalChannel    chan os.Signal
	restartSignalsChannel chan os.Signal
	proxyFactory          base.ProxyFactory
}

// NewServer creates new SServer.
func NewServer(config *Config, proxyFactory base.ProxyFactory, errorChan chan os.Signal, restarChan chan os.Signal) (server *SServer, err error) {
	return &SServer{
		config:                config,
		connectionManager:     network.NewConnectionManager(),
		errorSignalChannel:    errorChan,
		restartSignalsChannel: restarChan,
		proxyFactory:          proxyFactory,
	}, nil
}

// Close all listeners and return first error
func (server *SServer) Close() {
	log.Debugln("Closing server listeners..")
	var err error
	for _, listener := range server.listeners {
		listener = network.UnwrapSafeCloseListener(listener)
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
		default:
			if err = listener.Close(); err != nil {
				log.WithError(err).Warningln("Error on closing listener")
			}
		}
	}
	if err != nil {
		log.WithError(err).Infoln("server.Close()")
	}
	if err := server.connectionManager.CloseConnections(); err != nil {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnectionToService).WithError(err).Errorln("Error on close connections")
	}
	log.Debugln("Closed server listeners")
}

func (server *SServer) addListener(listener net.Listener) {
	server.listeners = append(server.listeners, listener)
}

type callbackData struct {
	connectionType string
	funcName       string
	callbackFunc   func(context.Context, []byte, net.Conn)
}

/*
handle new connection by initializing secure session, starting proxy request
to db and decrypting responses from db
*/
func (server *SServer) handleConnection(ctx context.Context, clientID []byte, connection net.Conn) {
	logger := logging.NewLoggerWithTrace(ctx)
	logging.SetLoggerToContext(ctx, logger)
	clientSession, err := NewClientSession(ctx, server.config.GetKeyStore(), server.config, connection)
	clientSession.Server = server
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitClientSession).
			Errorln("Can't initialize client session")
		if closeErr := connection.Close(); closeErr != nil {
			logger.WithError(closeErr).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnection).
				Errorln("Can't close connection")
		}
		return
	}
	clientSession.HandleClientConnection(clientID, server.proxyFactory)
}

func (server *SServer) processConnection(connection net.Conn, callback *callbackData) {
	connectionCounter.WithLabelValues(callback.connectionType).Inc()
	timer := prometheus.NewTimer(prometheus.ObserverFunc(connectionProcessingTimeHistogram.WithLabelValues(callback.connectionType).Observe))
	defer timer.ObserveDuration()

	ctx := logging.SetTraceStatus(context.Background(), server.config.TraceToLog)

	wrapCtx, wrapSpan := trace.StartSpan(ctx, "WrapServer", server.config.GetTraceOptions()...)
	logger := logging.NewLoggerWithTrace(wrapCtx)

	wrappedConnection, clientID, err := server.config.ConnectionWrapper.WrapServer(wrapCtx, connection)
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantWrapConnection).
			Errorln("Can't wrap connection from acra-connector")
		if closeErr := connection.Close(); closeErr != nil {
			logger.WithError(closeErr).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnection).
				Errorln("Can't close connection")
		}
		wrapSpan.End()
		return
	}
	logger = logger.WithField("client_id", string(clientID))
	wrapSpan.End()
	var span *trace.Span
	if server.config.WithConnector() {
		logger.Debugln("Read trace")
		spanContext, err := network.ReadTrace(wrappedConnection)
		if err != nil {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTracingCantReadTrace).WithError(err).Errorln("Can't read trace from AcraConnector")
			return
		}
		ctx, span = trace.StartSpanWithRemoteParent(wrapCtx, callback.funcName, spanContext, server.config.GetTraceOptions()...)
	} else {
		ctx, span = trace.StartSpan(wrapCtx, callback.funcName, server.config.GetTraceOptions()...)
	}
	ctx = logging.SetLoggerToContext(ctx, logger)
	span.AddAttributes(trace.BoolAttribute("from_connector", server.config.WithConnector()))
	defer span.End()
	wrapSpanContext := wrapSpan.SpanContext()
	// mark that wrapSpan related with new remote span
	span.AddLink(trace.Link{TraceID: wrapSpanContext.TraceID, SpanID: wrapSpanContext.SpanID, Type: trace.LinkTypeParent})
	callback.callbackFunc(ctx, clientID, wrappedConnection)
}

func (server *SServer) start(listener net.Listener, callback *callbackData, logger *log.Entry) {
	logger.Infof("Start listening connections")
	for {
		connection, err := listener.Accept()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorConnectionDroppedByTimeout).
					Errorln("Stop accepting new connections due net.Timeout")
				return
			}
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantAcceptNewConnections).
				Errorln("Can't accept new connection")
			return
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			logger.Infof("Got new connection to AcraServer: %v", connection.LocalAddr())
		} else {
			logger.Infof("Got new connection to AcraServer: %v", connection.RemoteAddr())
		}
		go func() {
			server.connectionManager.AddConnection(connection)
			server.processConnection(connection, callback)
			server.connectionManager.RemoveConnection(connection)
		}()
	}
}

// Start listening connections from proxy
func (server *SServer) Start() {
	logger := log.WithFields(log.Fields{"connection_string": server.config.GetAcraConnectionString(), "from_descriptor": false})
	logger.Infoln("Create listener")
	var listener, err = network.Listen(server.config.GetAcraConnectionString())
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartListenConnections).
			Errorln("Can't start listen connections")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}
	server.listenerACRA = listener
	server.addListener(listener)
	server.start(listener, &callbackData{funcName: "handleConnection", connectionType: dbConnectionType, callbackFunc: server.handleConnection}, logger)
}

// StartFromFileDescriptor starts listening Acra data connections from file descriptor.
func (server *SServer) StartFromFileDescriptor(fd uintptr) {
	logger := log.WithFields(log.Fields{"connection_string": server.config.GetAcraConnectionString(), "from_descriptor": true})
	file := os.NewFile(fd, "/tmp/acra-server")
	if file == nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCreateFileFromDescriptor).Errorln("Can't create new file from descriptor for acra listener")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}
	listenerFile, err := net.FileListener(file)
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantOpenFileByDescriptor).
			Errorln("System error: can't start listen for file descriptor")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}

	listenerWithFileDescriptor, ok := listenerFile.(network.ListenerWithFileDescriptor)
	if !ok {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorFileDescriptionIsNotValid).
			Errorf("System error: file descriptor %d is not a valid socket", fd)
		return
	}
	server.listenerACRA = listenerWithFileDescriptor
	server.addListener(listenerWithFileDescriptor)
	server.start(listenerWithFileDescriptor, &callbackData{funcName: "handleConnection", connectionType: dbConnectionType, callbackFunc: server.handleConnection}, logger)
}

// stopAcceptConnections stop accepting by setting deadline and then background code that call Accept will took error and
// stop execution
func stopAcceptConnections(listener network.DeadlineListener) (err error) {
	if listener != nil {
		err = listener.SetDeadline(time.Now())
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStopListenConnections).
				Errorln("Unable to SetDeadLine for listener")
		}
	} else {
		log.Warningln("Can't set deadline for server listener")
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
			log.WithError(err).Warningln("Listener doesn't support deadlines")
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
	server.connectionManager.Wait()
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
	return server.connectionManager.Counter
}

/*
handle new connection by initializing secure session, starting proxy request
to db and decrypting responses from db
*/
func (server *SServer) handleCommandsConnection(ctx context.Context, clientID []byte, connection net.Conn) {
	logger := logging.NewLoggerWithTrace(ctx)
	clientSession, err := NewClientCommandsSession(server.config.GetKeyStore(), server.config, connection)
	clientSession.Server = server
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartConnection).
			Errorln("Can't init API session")
		return
	}
	connection.SetDeadline(time.Now().Add(network.DefaultNetworkTimeout))
	clientSession.HandleSession()
	connection.SetDeadline(time.Time{})
}

// StartCommands starts listening commands connections from proxy.
func (server *SServer) StartCommands() {
	logger := log.WithFields(log.Fields{"connection_string": server.config.GetAcraAPIConnectionString(), "from_descriptor": false})
	var listener, err = network.Listen(server.config.GetAcraAPIConnectionString())
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartListenConnections).
			Errorln("Can't start listen command API connections")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}
	server.listenerAPI = listener
	server.addListener(listener)
	server.start(listener, &callbackData{funcName: "handleCommandsConnection", connectionType: apiConnectionType, callbackFunc: server.handleCommandsConnection}, logger)
}

// StartCommandsFromFileDescriptor starts listening commands connections from file descriptor.
func (server *SServer) StartCommandsFromFileDescriptor(fd uintptr) {
	logger := log.WithFields(log.Fields{"connection_string": server.config.GetAcraConnectionString(), "from_descriptor": true})
	file := os.NewFile(fd, "/tmp/acra-server_http_api")
	if file == nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCreateFileFromDescriptor).Errorln("Can't create new file from descriptor for API listener")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}
	listenerFile, err := net.FileListener(file)
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantOpenFileByDescriptor).
			Errorln("System error: can't start listen for file descriptor")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}
	listenerWithFileDescriptor, ok := listenerFile.(network.ListenerWithFileDescriptor)
	if !ok {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorFileDescriptionIsNotValid).
			Errorf("System error: file descriptor %d is not a valid socket", fd)
		return
	}
	server.listenerAPI = listenerWithFileDescriptor
	server.addListener(listenerWithFileDescriptor)
	server.start(listenerWithFileDescriptor, &callbackData{funcName: "handleCommandsConnection", connectionType: apiConnectionType, callbackFunc: server.handleCommandsConnection}, logger)
}
