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

package common

import (
	"context"
	"errors"
	"io"
	"net"
	url_ "net/url"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/utils"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
)

type closer func()

func (c closer) Close() error {
	c()
	return nil
}

// sessionCloseToCloser converts Close() to io.Closer Close() error
func sessionCloseToCloser(close func()) io.Closer {
	return closer(close)
}

func recoverConnection(logger *log.Entry, session io.Closer) {
	if recMsg := recover(); recMsg != nil {
		logger.WithField("error", recMsg).Errorln("Panic in connection processing, close connection")
		if err := session.Close(); err != nil {
			logger.WithError(err).Errorln("Error on Close() callback in panic handler")
		}
	}
}

// SServer represents AcraServer server, connects with KeyStorage, configuration file,
// data and command connections (listeners, managers, file descriptors), and signals.
type SServer struct {
	config                *Config
	listenerACRA          net.Listener
	listenerAPI           net.Listener
	connectionManager     *network.ConnectionManager
	listeners             []net.Listener
	errorSignalChannel    chan os.Signal
	restartSignalsChannel chan os.Signal
	proxyFactory          base.ProxyFactory
	backgroundWorkersSync sync.WaitGroup
	stopListenersSignal   chan bool
	errCh                 chan error
	lock                  sync.RWMutex
	stopOnce              sync.Once
	exitOnce              sync.Once
}

// ErrWaitTimeout error indicates that server was shutdown and waited N seconds while shutting down all connections.
var ErrWaitTimeout = errors.New("timeout")

// Close all listeners and return first error
func (server *SServer) Close() {
	log.Debugln("Closing server listeners..")
	var err error
	server.lock.RLock()
	defer server.lock.RUnlock()
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
	server.lock.Lock()
	server.listeners = append(server.listeners, listener)
	server.lock.Unlock()
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
	clientSession, err := NewClientSession(ctx, server.config, connection)
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitClientSession).
			Errorln("Can't initialize client session")
		if closeErr := connection.Close(); closeErr != nil {
			logger.WithError(closeErr).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnection).
				Errorln("Can't close connection")
		}
		return
	}
	server.handleClientSession(clientID, clientSession)
}

func (server *SServer) handleClientSession(clientID []byte, clientSession *ClientSession) {
	sessionLogger := clientSession.Logger()
	sessionLogger.Infof("Handle client's connection")
	proxyErrCh := make(chan base.ProxyError)

	sessionLogger.Debugf("Connecting to db")
	err := clientSession.ConnectToDb()
	if err != nil {
		sessionLogger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantConnectToDB).
			Errorln("Can't connect to db")

		sessionLogger.Debugln("Close connection with acra-connector")
		err = clientSession.ClientConnection().Close()
		if err != nil {
			sessionLogger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnectionToService).
				Errorln("Error with closing connection to acra-connector")
		}
		return
	}
	proxy, err := server.proxyFactory.New(clientID, clientSession)
	if err != nil {
		sessionLogger.WithError(err).Errorln("Can't create new proxy for connection")
		return
	}
	accessContext := base.NewAccessContext(base.WithClientID(clientID))
	// subscribe on clientID changes after switching connection to TLS and using ClientID from TLS certificates
	proxy.AddClientIDObserver(accessContext)
	clientSession.ctx = base.SetAccessContextToContext(clientSession.ctx, accessContext)

	// We launch two goroutines to serve the client and db-side asynchronously.
	// Synchronous processing, like:
	// read from client - edit - send to server - read response - edit - send to the client
	// doesn't work because, because some messages are asynchronous (for example
	// https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-ASYNC)
	server.backgroundWorkersSync.Add(1)
	go func() {
		defer server.backgroundWorkersSync.Done()
		defer recoverConnection(sessionLogger.WithField("function", "ProxyClientConnection"), sessionCloseToCloser(clientSession.Close))
		proxy.ProxyClientConnection(clientSession.ctx, proxyErrCh)
	}()
	server.backgroundWorkersSync.Add(1)
	go func() {
		defer server.backgroundWorkersSync.Done()
		defer recoverConnection(sessionLogger.WithField("function", "ProxyDatabaseConnection"), sessionCloseToCloser(clientSession.Close))
		proxy.ProxyDatabaseConnection(clientSession.ctx, proxyErrCh)
	}()

	proxyErr := <-proxyErrCh
	sessionLogger = sessionLogger.WithField("interrupt_side", proxyErr.InterruptSide())
	sessionLogger.Debugln("Stop to proxy")

	err = errors.Unwrap(proxyErr)
	if err == io.EOF {
		sessionLogger.Debugln("EOF connection closed")
	} else if err == nil {
		sessionLogger.Debugln("Err == nil from proxy goroutine")
	} else if netErr, ok := err.(net.Error); ok {
		sessionLogger.WithError(netErr).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneralConnectionProcessing).Errorln("Network error")
	} else if opErr, ok := err.(*net.OpError); ok {
		sessionLogger.WithError(opErr).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneralConnectionProcessing).Errorln("Network error")
	} else if filesystem.IsKeyReadError(err) {
		sessionLogger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneralConnectionProcessing).Errorln("Key found error")
	} else {
		sessionLogger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneralConnectionProcessing).Errorln("Unexpected error")
	}

	sessionLogger.Infof("Closing client's connection")
	clientSession.Close()

	// wait second error from closed second connection
	sessionLogger.WithError(<-proxyErrCh).Debugln("Second proxy goroutine stopped")
	sessionLogger.Infoln("Finished processing client's connection")
}

func (server *SServer) processConnection(parentContext context.Context, connection net.Conn, callback *callbackData) {
	connectionCounter.WithLabelValues(callback.connectionType).Inc()
	timer := prometheus.NewTimer(prometheus.ObserverFunc(connectionProcessingTimeHistogram.WithLabelValues(callback.connectionType).Observe))
	defer timer.ObserveDuration()

	ctx := logging.SetTraceStatus(parentContext, server.config.TraceToLog)

	wrapCtx, wrapSpan := trace.StartSpan(ctx, "WrapServer", server.config.GetTraceOptions()...)
	logger := logging.NewLoggerWithTrace(wrapCtx)

	wrappedConnection, clientID, err := server.config.ConnectionWrapper.WrapServer(wrapCtx, connection)
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantWrapConnection).
			Errorln("Can't wrap connection")
		if closeErr := connection.Close(); closeErr != nil {
			logger.WithError(closeErr).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnection).
				Errorln("Can't close connection")
		}
		wrapSpan.End()
		return
	}
	logger = logger.WithField("client_id", string(clientID))
	wrapSpan.End()
	ctx, span := trace.StartSpan(wrapCtx, callback.funcName, server.config.GetTraceOptions()...)
	ctx = logging.SetLoggerToContext(ctx, logger)
	defer span.End()
	wrapSpanContext := wrapSpan.SpanContext()
	// mark that wrapSpan related with new remote span
	span.AddLink(trace.Link{TraceID: wrapSpanContext.TraceID, SpanID: wrapSpanContext.SpanID, Type: trace.LinkTypeParent})
	callback.callbackFunc(ctx, clientID, wrappedConnection)
}

func (server *SServer) start(parentContext context.Context, listener net.Listener, callback *callbackData, logger *log.Entry, errCh chan<- error) {
	logger.Infof("Start listening connections")
	for {
		select {
		case <-parentContext.Done():
			return
		default:
			break
		}

		connection, err := listener.Accept()
		if err != nil {
			select {
			case <-server.stopListenersSignal:
				// situation when listener is stopped while accepting.
				// This is typical for shutdown that invokes StopListeners functions, which closes signalling channel, just skip
			default:
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorConnectionDroppedByTimeout).
						Errorln("Stop accepting new connections due net.Timeout")
				} else {
					logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantAcceptNewConnections).
						Errorln("Can't accept new connection")
				}
				errCh <- err
			}
			return
		}
		// unix socket and value == '@'
		if len(connection.RemoteAddr().String()) == 1 {
			logger.Infof("Got new connection to AcraServer: %v", connection.LocalAddr())
		} else {
			logger.Infof("Got new connection to AcraServer: %v", connection.RemoteAddr())
		}

		server.backgroundWorkersSync.Add(1)
		go func() {
			defer server.backgroundWorkersSync.Done()
			defer recoverConnection(logger.WithFields(
				log.Fields{"connection_type": callback.connectionType, "function": callback.funcName}), connection)

			_ = server.connectionManager.AddConnection(connection)
			server.processConnection(parentContext, connection, callback)
			_ = server.connectionManager.RemoveConnection(connection)
		}()
	}
}

// ListenerAcra returns listener for AcraServer database connections.
func (server *SServer) ListenerAcra() net.Listener {
	return server.listenerACRA
}

// ListenerAPI returns listener for AcraServer management API connections.
func (server *SServer) ListenerAPI() net.Listener {
	return server.listenerAPI
}

func (server *SServer) waitForExitTimeout() {
	// We should use this function when shutdown service as a defer. In this case global 'cancel'
	// has been called. Now we should wait (not more than specified duration) until all
	// background goroutines spawned by SServer will finish their execution or force their closing.
	if utils.WaitWithTimeout(&server.backgroundWorkersSync, utils.DefaultWaitGroupTimeoutDuration) {
		log.Errorf("Couldn't stop all background goroutines spawned by readerServer. Exited by timeout")
	}
}

// Start listening connections from proxy
func (server *SServer) Start(parentContext context.Context) {
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
	server.run(parentContext, listener, &callbackData{funcName: "handleConnection", connectionType: dbConnectionType, callbackFunc: server.handleConnection}, logger)
}

// StartFromFileDescriptor starts listening Acra data connections from file descriptor.
func (server *SServer) StartFromFileDescriptor(parentContext context.Context, fd uintptr) {
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
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}
	server.listenerACRA = listenerWithFileDescriptor
	server.addListener(listenerWithFileDescriptor)
	server.run(parentContext, listenerWithFileDescriptor, &callbackData{funcName: "handleConnection", connectionType: dbConnectionType, callbackFunc: server.handleConnection}, logger)
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
	server.stopOnce.Do(func() {
		// Use this channel for signaling of closed listeners according to
		// https://stackoverflow.com/questions/13417095/how-do-i-stop-a-listening-server-in-go
		close(server.stopListenersSignal)

		var err error
		var deadlineListener network.DeadlineListener
		log.Debugln("Stopping listeners")
		server.lock.RLock()
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
		server.lock.RUnlock()
	})
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

// StartCommands starts listening commands connections from proxy.
func (server *SServer) StartCommands(parentContext context.Context) {
	logger := log.WithFields(log.Fields{"connection_string": server.config.GetAcraAPIConnectionString(), "from_descriptor": false})
	var listener, err = network.Listen(server.config.GetAcraAPIConnectionString())
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantStartListenConnections).
			Errorln("Can't start listen command API connections")
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}
	server.config.HTTPAPIConnectionWrapper.SetListener(listener)
	listener = server.config.HTTPAPIConnectionWrapper
	server.listenerAPI = listener
	server.addListener(listener)
	server.runCommands(parentContext, listener, logger)
}

func (server *SServer) runCommands(ctx context.Context, listener net.Listener, logger *log.Entry) {
	defer server.waitForExitTimeout()

	connContextCallback := server.config.HTTPAPIConnectionWrapper.OnConnectionContext
	apiServer := NewHTTPAPIServer(
		ctx,
		server.config.GetKeyStore(),
		server.config.TraceToLog,
		server.config.GetTraceOptions(),
		server.config.GetTLSClientIDExtractor(),
		connContextCallback,
	)
	err := apiServer.Start(listener, &server.backgroundWorkersSync)
	if err != nil {
		// TODO: what status code to use?
		logger.WithError(err).Errorln("Handling HTTP API requests")
	}
}

// StartCommandsFromFileDescriptor starts listening commands connections from file descriptor.
func (server *SServer) StartCommandsFromFileDescriptor(parentContext context.Context, fd uintptr) {
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
		server.errorSignalChannel <- syscall.SIGTERM
		return
	}
	server.listenerAPI = listenerWithFileDescriptor
	server.addListener(listenerWithFileDescriptor)
	server.runCommands(parentContext, listenerWithFileDescriptor, logger)
}

func (server *SServer) run(parentContext context.Context, listener net.Listener, data *callbackData, logger *log.Entry) {
	defer server.waitForExitTimeout()

	var errCh = make(chan error)
	server.backgroundWorkersSync.Add(1)
	go func() {
		defer server.backgroundWorkersSync.Done()
		server.start(parentContext, listener, data, logger, errCh)
	}()

	select {
	case <-parentContext.Done():
		break
	case outErr := <-errCh:
		if outErr != nil {
			logger.WithError(outErr).Errorln("Error occurred on accepting/handling connection")
		}
		break
	}
	return
}
