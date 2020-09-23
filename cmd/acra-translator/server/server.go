/*
Copyright 2018, Cossack Labs Limited

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

package server

import (
	"context"
	"errors"
	"github.com/cossacklabs/acra/utils"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"

	"bufio"
	"net/http"

	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	"github.com/cossacklabs/acra/cmd/acra-translator/http_api"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
	"google.golang.org/grpc"
)

// ReaderServer represents AcraTranslator server, connects with KeyStorage, configuration file,
// gRPC and HTTP request parsers.
type ReaderServer struct {
	config                *common.AcraTranslatorConfig
	keystorage            keystore.TranslationKeyStore
	connectionManager     *network.ConnectionManager
	grpcServer            *grpc.Server
	httpDecryptor         *http_api.HTTPConnectionsDecryptor
	waitTimeout           time.Duration
	grpcServerFactory     common.GRPCServerFactory
	backgroundWorkersSync sync.WaitGroup
	listenerHTTP          net.Listener
	listenerGRPC          net.Listener
}

const (
	grpcFilenamePlaceholder = "tmp/acra_translator_grpc"
	httpFilenamePlaceholder = "tmp/acra_translator_http"
)

// NewReaderServer creates Reader server with provided params.
func NewReaderServer(config *common.AcraTranslatorConfig, keystorage keystore.TranslationKeyStore, grpcServerFactory common.GRPCServerFactory, waitTimeout time.Duration) (server *ReaderServer, err error) {
	return &ReaderServer{
		grpcServerFactory: grpcServerFactory,
		waitTimeout:       waitTimeout,
		config:            config,
		keystorage:        keystorage,
		connectionManager: network.NewConnectionManager(),
	}, nil
}

// Stop stops AcraTranslator from accepting new connections, and gracefully close existing ones.
func (server *ReaderServer) Stop() {
	log.Infoln("Stop accepting new connections")
	server.StopListeners()

	// non block stop
	if server.grpcServer != nil {
		server.backgroundWorkersSync.Add(1)
		go func() {
			defer server.backgroundWorkersSync.Done()
			server.grpcServer.GracefulStop()
		}()
	}

	if server.connectionManager.Counter != 0 {
		log.Infof("Wait ending current connections (%v)", server.connectionManager.Counter)
		// wait existing connections to end request
		<-time.NewTimer(server.waitTimeout).C
	}

	log.Infof("Stop all connections that not closed (%v)", server.connectionManager.Counter)
	if server.grpcServer != nil {
		// force stop of grpc server
		server.grpcServer.Stop()
	}
	// force close all connections
	if err := server.connectionManager.CloseConnections(); err != nil {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnection).WithError(err).Errorln("Took error on closing available connections")
	}
}

// HandleHTTPConnection handles each connection with HTTP request handler
func (server *ReaderServer) HandleHTTPConnection(parentContext context.Context, listener net.Listener, connectionString string, processingFunc ProcessingFunc) error {
	logger := logging.GetLoggerFromContext(parentContext)
	if logger == nil {
		logger = log.NewEntry(log.StandardLogger())
	}
	logger = log.WithField("connection_string", connectionString)

	errCh := make(chan error)

	// start accept new connections from connectionString
	connectionChannel, err := common.AcceptConnections(parentContext, listener, errCh)
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantAcceptNewConnections).WithError(err).Errorf("Can't start to handle connection string %v", connectionString)
		return err
	}
	// use to send close packets to all unclosed connections at end
	server.backgroundWorkersSync.Add(1)
	go func() {
		defer server.backgroundWorkersSync.Done()
		logger.WithField("connection_string", connectionString).Debugln("Start wrap new connections")
		for {
			var connection net.Conn
			select {
			case connection = <-connectionChannel:
				break
			case <-parentContext.Done():
				if !errors.Is(parentContext.Err(), context.Canceled) {
					logger.WithError(parentContext.Err()).Debugln("Stop wrapping new connections")
				}
				return
			}

			connectionContext := context.TODO()
			wrappedConnection, clientID, err := server.config.ConnectionWrapper.WrapServer(connectionContext, connection)
			if err != nil {
				logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantWrapConnectionToSS).
					Errorln("Can't wrap new connection")
				if err := connection.Close(); err != nil {
					logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantCloseConnection).
						Errorln("Can't close connection")
				}
				continue
			}
			logger = logger.WithField("client_id", string(clientID))
			logger.Debugln("Read trace")
			spanContext, err := network.ReadTrace(wrappedConnection)
			if err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTracingCantReadTrace).WithError(err).Errorln("Can't read trace from wrapped connection")
				if err := wrappedConnection.Close(); err != nil {
					log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantWrapConnection).WithError(err).Errorln("Can't close wrapped connection")
				}
				continue
			}
			ctx, span := trace.StartSpanWithRemoteParent(connectionContext, connection.RemoteAddr().String(), spanContext, server.config.GetTraceOptions()...)
			logger.Debugln("Pass wrapped connection to processing function")
			logging.SetLoggerToContext(ctx, logger)

			server.backgroundWorkersSync.Add(1)
			go func() {
				defer func() {
					span.End()
					err := wrappedConnection.Close()
					if err != nil {
						logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantCloseConnection).
							Errorln("Can't close wrapped connection")
					}
					logger.Infoln("Connection closed")
					server.backgroundWorkersSync.Done()
				}()

				if err := server.connectionManager.AddConnection(wrappedConnection); err != nil {
					logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPConnection).
						Errorln("Can't add connection to connection manager")
					return
				}

				processingFunc(ctx, clientID, wrappedConnection)

				if err := server.connectionManager.RemoveConnection(wrappedConnection); err != nil {
					logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPConnection).
						Errorln("Can't remove connection from connection manager")
				}
			}()
		}
	}()
	var outErr error
	select {
	case <-parentContext.Done():
		outErr = parentContext.Err()
	case outErr = <-errCh:
		if outErr != nil {
			log.WithError(outErr).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantAcceptNewHTTPConnection).
				Errorln("Error on accepting new connections")
		}
	}
	return outErr
}

// Start setups gRPC handler or HTTP handler, poison records callbacks and starts listening to connections.
func (server *ReaderServer) Start(parentContext context.Context) {
	defer server.waitForExitTimeout()

	logger := logging.GetLoggerFromContext(parentContext)
	poisonCallbacks := base.NewPoisonCallbackStorage()
	server.detectPoisonRecords(poisonCallbacks)
	errCh := make(chan error)

	decryptorData := &common.TranslatorData{Keystorage: server.keystorage, PoisonRecordCallbacks: poisonCallbacks, CheckPoisonRecords: server.config.DetectPoisonRecords()}
	if server.config.IncomingConnectionHTTPString() != "" {
		listener, err := network.Listen(server.config.IncomingConnectionHTTPString())
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantAcceptNewHTTPConnection).
				Errorln("Can't create HTTP listener from specified connection string")
			return
		}
		server.listenerHTTP = listener
		server.startHTTP(parentContext, logger, decryptorData, errCh, listener)
	}

	// provide way to register new services and custom server
	if server.config.IncomingConnectionGRPCString() != "" {
		listener, err := network.Listen(server.config.IncomingConnectionGRPCString())
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantAcceptNewGRPCConnection).
				Errorln("Can't create gRPC listener from specified connection string")
			return
		}
		server.listenerGRPC = listener
		server.startGRPC(logger, decryptorData, errCh, listener)
	}

	select {
	case <-parentContext.Done():
		break
	case outErr := <-errCh:
		if outErr != nil {
			log.WithError(outErr).Errorln("Can't correctly exit from readerServer component")
		}
		break
	}
	return
}

func (server *ReaderServer) startHTTP(parentContext context.Context, logger *log.Entry, decryptorData *common.TranslatorData, errCh chan<- error, listener net.Listener) {
	server.backgroundWorkersSync.Add(1)
	go func() {
		defer server.backgroundWorkersSync.Done()
		httpContext := logging.SetLoggerToContext(parentContext, logger.WithField(ConnectionTypeKey, HTTPConnectionType))
		httpDecryptor, err := http_api.NewHTTPConnectionsDecryptor(decryptorData)
		logger.WithField("connection_string", server.config.IncomingConnectionHTTPString()).Infof("Start process HTTP requests")
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPConnection).
				Errorln("Can't create HTTP decryptor")
			errCh <- err
			return
		}
		server.httpDecryptor = httpDecryptor
		err = server.HandleHTTPConnection(httpContext, listener, server.config.IncomingConnectionHTTPString(), server.processHTTPConnection)
		if err != nil {
			// It is a "normal" case, when we shutdown service - we call 'cancel' on main level in SIGTERM/SIGINT handlers,
			// so let's avoid treating context.Canceled as error here
			if !errors.Is(err, context.Canceled) {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPConnection).
					Errorln("Took error on handling HTTP requests")
				server.Stop()
				errCh <- err
			}
			return
		}
	}()
}

func (server *ReaderServer) startGRPC(logger *log.Entry, decryptorData *common.TranslatorData, errCh chan<- error, listener net.Listener) {
	server.backgroundWorkersSync.Add(1)
	go func() {
		defer server.backgroundWorkersSync.Done()
		grpcLogger := logger.WithField(ConnectionTypeKey, GRPCConnectionType)
		logger.WithField("connection_string", server.config.IncomingConnectionGRPCString()).Infof("Start process gRPC requests")
		var err error
		var opts []grpc.ServerOption
		if server.config.WithTLS() {
			opts = append(opts, grpc.Creds(credentials.NewTLS(server.config.GetTLSConfig())))
		} else {
			wrapper, err := network.NewSecureSessionConnectionWrapper(server.config.ServerID(), server.keystorage)
			if err != nil {
				grpcLogger.WithError(err).Errorln("Can't initialize Secure Session wrapper")
				errCh <- err
				return
			}
			opts = append(opts, grpc.Creds(wrapper))
		}

		server.listenerGRPC = listener
		grpcListener := common.WrapListenerWithMetrics(listener)
		grpcServer, err := server.grpcServerFactory.New(decryptorData, opts...)
		if err != nil {
			logger.WithError(err).Errorln("Can't create new gRPC server")
			errCh <- err
			return
		}
		server.grpcServer = grpcServer
		if err := grpcServer.Serve(grpcListener); err != nil {
			grpcLogger.Errorf("failed to serve: %v", err)
			server.Stop()
			errCh <- err
			return
		}
	}()
}

func (server *ReaderServer) detectPoisonRecords(poisonCallbackStorage *base.PoisonCallbackStorage) {
	if server.config.DetectPoisonRecords() {
		if server.config.ScriptOnPoison() != "" {
			log.Infof("Add poison record callback with script execution %v", server.config.ScriptOnPoison())
			poisonCallbackStorage.AddCallback(base.NewExecuteScriptCallback(server.config.ScriptOnPoison()))
		}

		// must be last
		if server.config.StopOnPoison() {
			log.Infoln("Add poison record callback with AcraTranslator termination")
			poisonCallbackStorage.AddCallback(&base.StopCallback{})
		}
	}
}

func (server *ReaderServer) waitForExitTimeout() {
	// We should use this function when shutdown service as a defer. In this case global 'cancel'
	// has been called. Now we should wait (not more than specified duration) until all
	// background goroutines spawned by readerServer will finish their execution or force their closing.
	// Another case is error while initialization of http/grpc (while creating listeners)
	if utils.WaitWithTimeout(&server.backgroundWorkersSync, utils.DefaultWaitGroupTimeoutDuration) {
		log.Errorf("Couldn't stop all background goroutines spawned by readerServer. Exited by timeout")
	}
}

// StartFromFileDescriptor starts listening commands connections from file descriptor.
func (server *ReaderServer) StartFromFileDescriptor(parentContext context.Context, fdHTTP, fdGRPC uintptr) {
	defer server.waitForExitTimeout()

	logger := logging.GetLoggerFromContext(parentContext)
	poisonCallbacks := base.NewPoisonCallbackStorage()
	server.detectPoisonRecords(poisonCallbacks)
	errCh := make(chan error)

	decryptorData := &common.TranslatorData{Keystorage: server.keystorage, PoisonRecordCallbacks: poisonCallbacks, CheckPoisonRecords: server.config.DetectPoisonRecords()}
	if server.config.IncomingConnectionHTTPString() != "" {
		// create HTTP listener from correspondent file descriptor
		file := os.NewFile(fdHTTP, httpFilenamePlaceholder)
		if file == nil {
			logger.Errorln("Can't create new file from descriptor for Acra HTTP listener")
			return
		}
		listenerFile, err := net.FileListener(file)
		if err != nil {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantOpenFileByDescriptor).
				Errorln("System error: can't start listen for file descriptor")
			return
		}

		listenerWithFileDescriptor, ok := listenerFile.(network.ListenerWithFileDescriptor)
		if !ok {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorFileDescriptionIsNotValid).
				Errorf("System error: file descriptor %d is not a valid socket", fdHTTP)
			return
		}
		server.listenerHTTP = listenerWithFileDescriptor
		server.startHTTP(parentContext, logger, decryptorData, errCh, listenerWithFileDescriptor)
	}

	// provide way to register new services and custom server
	if server.config.IncomingConnectionGRPCString() != "" {
		// load gRPC listener from correspondent file descriptor
		file := os.NewFile(fdGRPC, grpcFilenamePlaceholder)
		if file == nil {
			logger.Errorln("Can't create new file from descriptor for Acra gRPC listener")
			return
		}
		listenerFile, err := net.FileListener(file)
		if err != nil {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantOpenFileByDescriptor).
				Errorln("System error: can't start listen for file descriptor")
			return
		}

		listenerWithFileDescriptor, ok := listenerFile.(network.ListenerWithFileDescriptor)
		if !ok {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorFileDescriptionIsNotValid).
				Errorf("System error: file descriptor %d is not a valid socket", fdGRPC)
			return
		}
		server.listenerGRPC = listenerWithFileDescriptor
		server.startGRPC(logger, decryptorData, errCh, listenerWithFileDescriptor)
	}

	select {
	case <-parentContext.Done():
		break
	case outErr := <-errCh:
		if outErr != nil {
			log.WithError(outErr).Errorln("Can't correctly exit from readerServer component")
		}
		break
	}
	return
}

// ProcessingFunc redirects processing of connection to HTTP handler or gRPC handler.
type ProcessingFunc func(context.Context, []byte, net.Conn)

func (server *ReaderServer) processHTTPConnection(parentContext context.Context, clientID []byte, connection net.Conn) {
	connection.SetDeadline(time.Now().Add(network.DefaultNetworkTimeout))
	defer connection.SetDeadline(time.Time{})

	spanCtx, span := trace.StartSpan(parentContext, "processHTTPConnection")
	defer span.End()

	// processing HTTP connection
	logger := logging.LoggerWithTrace(spanCtx, logging.GetLoggerFromContext(parentContext))
	httpLogger := logger.WithField(ConnectionTypeKey, HTTPConnectionType)
	httpLogger.Debugln("HTTP handler")

	reader := bufio.NewReader(connection)
	request, err := http.ReadRequest(reader)

	// TODO: handle keep alive

	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPRequest).
			Warningln("Got new HTTP request, but can't read it")
		server.httpDecryptor.SendResponse(logger,
			server.httpDecryptor.EmptyResponseWithStatus(request, http.StatusBadRequest), connection)
		return
	}

	response := server.httpDecryptor.ParseRequestPrepareResponse(logger, request, clientID)
	server.httpDecryptor.SendResponse(logger, response, connection)
}

// Constants show possible connection types.
const (
	ConnectionTypeKey  = "connection_type"
	HTTPConnectionType = "http"
	GRPCConnectionType = "grpc"
)

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

// StopListeners stops our HTTP/GRPC listeners from accepting new connections
func (server *ReaderServer) StopListeners() {
	log.Debugln("Stopping listeners")
	if server.listenerHTTP != nil {
		err := stopListener(server.listenerHTTP)
		if err != nil {
			log.WithError(err).Warningln("Error occured while stopping HTTP listener")
		}
	}
	if server.listenerGRPC != nil {
		err := stopListener(server.listenerGRPC)
		if err != nil {
			log.WithError(err).Warningln("Error occured while stopping gRPC listener")
		}
	}
	log.Debugln("Listeners have been stopped")
}

func stopListener(listener net.Listener) error {
	deadlineListener, err := network.CastListenerToDeadline(listener)
	if err != nil {
		return err
	}
	if err = stopAcceptConnections(deadlineListener); err != nil {
		return err
	}
	return nil
}

// GetHTTPListener returns HTTP listener object
func (server *ReaderServer) GetHTTPListener() net.Listener {
	return server.listenerHTTP
}

// GetGRPCListener returns GRPC listener object
func (server *ReaderServer) GetGRPCListener() net.Listener {
	return server.listenerGRPC
}

// GetConnectionManager returns ConnectionManager object
func (server *ReaderServer) GetConnectionManager() *network.ConnectionManager {
	return server.connectionManager
}
