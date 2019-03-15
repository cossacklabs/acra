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

package main

import (
	"context"
	"go.opencensus.io/trace"
	"net"
	"os"
	"time"

	"bufio"
	"net/http"

	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	"github.com/cossacklabs/acra/cmd/acra-translator/grpc_api"
	"github.com/cossacklabs/acra/cmd/acra-translator/http_api"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// ReaderServer represents AcraTranslator server, connects with KeyStorage, configuration file,
// gRPC and HTTP request parsers.
type ReaderServer struct {
	config            *AcraTranslatorConfig
	keystorage        keystore.KeyStore
	connectionManager *network.ConnectionManager
	grpcServer        *grpc.Server

	httpDecryptor *http_api.HTTPConnectionsDecryptor

	waitTimeout time.Duration

	listenersContextCancel []context.CancelFunc
}

// NewReaderServer creates Reader server with provided params.
func NewReaderServer(config *AcraTranslatorConfig, keystorage keystore.KeyStore, waitTimeout time.Duration) (server *ReaderServer, err error) {
	return &ReaderServer{
		waitTimeout:       waitTimeout,
		config:            config,
		keystorage:        keystorage,
		connectionManager: network.NewConnectionManager(),
	}, nil
}

// Stop stops AcraTranslator from accepting new connections, and gracefully close existing ones.
func (server *ReaderServer) Stop() {
	log.Infoln("Stop accepting new connections")
	// stop all listeners
	for _, cancelFunc := range server.listenersContextCancel {
		cancelFunc()
	}
	// non block stop
	if server.grpcServer != nil {
		go server.grpcServer.GracefulStop()
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

func (server *ReaderServer) listenerContext(parentContext context.Context) context.Context {
	ctx, cancel := context.WithCancel(parentContext)
	server.listenersContextCancel = append(server.listenersContextCancel, cancel)
	return ctx
}

// HandleConnectionString handles each connection with gRPC request handler or HTTP request handler
// depending on connection string.
func (server *ReaderServer) HandleConnectionString(parentContext context.Context, connectionString string, processingFunc ProcessingFunc) error {
	logger := logging.GetLoggerFromContext(parentContext)
	if logger == nil {
		logger = log.NewEntry(log.StandardLogger())
	}
	logger = log.WithField("connection_string", connectionString)

	errCh := make(chan error)

	listenerContext := server.listenerContext(parentContext)

	// start accept new connections from connectionString
	connectionChannel, err := AcceptConnections(listenerContext, connectionString, errCh)
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantAcceptNewConnections).WithError(err).Errorf("Can't start to handle connection string %v", connectionString)
		return err
	}
	// use to send close packets to all unclosed connections at end
	go func() {
		logger.WithField("connection_string", connectionString).Debugln("Start wrap new connections")
		for {
			var connection net.Conn
			select {
			case connection = <-connectionChannel:
				break
			case <-parentContext.Done():
				logger.WithError(parentContext.Err()).Debugln("Stop wrapping new connections")
				return
			}

			wrappedConnection, clientID, err := server.config.ConnectionWrapper.WrapServer(context.TODO(), connection)
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
			ctx, span := trace.StartSpanWithRemoteParent(listenerContext, getHandlerName(listenerContext), spanContext, server.config.GetTraceOptions()...)
			logger.Debugln("Pass wrapped connection to processing function")
			logging.SetLoggerToContext(ctx, logger)

			go func() {
				defer func() {
					span.End()
					err := wrappedConnection.Close()
					if err != nil {
						logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantCloseConnection).
							Errorln("Can't close wrapped connection")
					}
					logger.Infoln("Connection closed")
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
		log.WithError(parentContext.Err()).Debugln("Exit from handling connection string. Close all connections")
		outErr = parentContext.Err()
	case outErr = <-errCh:
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantAcceptNewHTTPConnection).
			Errorln("Error on accepting new connections")
		server.Stop()
	}
	return outErr
}

// Constants show possible connection types.
const (
	ConnectionTypeKey  = "connection_type"
	HTTPConnectionType = "http"
	GRPCConnectionType = "grpc"
)

type handlerName struct{}

func withHandlerName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, handlerName{}, name)
}

func getHandlerName(ctx context.Context) string {
	if s, ok := ctx.Value(handlerName{}).(string); ok {
		return s
	}
	return "undefined"
}

// Start setups gRPC handler or HTTP handler, poison records callbacks and starts listening to connections.
func (server *ReaderServer) Start(parentContext context.Context) {
	logger := logging.GetLoggerFromContext(parentContext)
	poisonCallbacks := base.NewPoisonCallbackStorage()
	if server.config.DetectPoisonRecords() {
		if server.config.scriptOnPoison != "" {
			log.Infof("Add poison record callback with script execution %v", server.config.scriptOnPoison)
			poisonCallbacks.AddCallback(base.NewExecuteScriptCallback(server.config.scriptOnPoison))
		}

		// must be last
		if server.config.stopOnPoison {
			log.Infoln("Add poison record callback with AcraTranslator termination")
			poisonCallbacks.AddCallback(&base.StopCallback{})
		}
	}
	decryptorData := &common.TranslatorData{Keystorage: server.keystorage, PoisonRecordCallbacks: poisonCallbacks, CheckPoisonRecords: server.config.detectPoisonRecords}
	if server.config.incomingConnectionHTTPString != "" {
		go func() {
			httpContext := logging.SetLoggerToContext(parentContext, logger.WithField(ConnectionTypeKey, HTTPConnectionType))
			httpDecryptor, err := http_api.NewHTTPConnectionsDecryptor(decryptorData)
			logger.WithField("connection_string", server.config.incomingConnectionHTTPString).Infof("Start process HTTP requests")
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPConnection).
					Errorln("Can't create HTTP decryptor")
			}
			server.httpDecryptor = httpDecryptor
			err = server.HandleConnectionString(withHandlerName(httpContext, "processHTTPConnection"), server.config.incomingConnectionHTTPString, server.processHTTPConnection)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPConnection).
					Errorln("Took error on handling HTTP requests")
				server.Stop()
				os.Exit(1)
			}
		}()
	}
	if server.config.incomingConnectionGRPCString != "" {
		go func() {
			grpcLogger := logger.WithField(ConnectionTypeKey, GRPCConnectionType)
			logger.WithField("connection_string", server.config.incomingConnectionGRPCString).Infof("Start process gRPC requests")
			secureSessionListener, err := network.NewSecureSessionListener(server.config.ServerID(), server.config.incomingConnectionGRPCString, server.keystorage)
			if err != nil {
				grpcLogger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleGRPCConnection).
					Errorln("Can't create secure session listener")
				return
			}
			grpcListener := WrapListenerWithMetrics(secureSessionListener)

			grpcServer := grpc.NewServer(grpc.ConnectionTimeout(network.DefaultNetworkTimeout))
			service, err := grpc_api.NewDecryptGRPCService(decryptorData)
			if err != nil {
				grpcLogger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleGRPCConnection).
					Errorln("Can't create grpc service")
				return
			}
			grpc_api.RegisterReaderServer(grpcServer, service)
			server.grpcServer = grpcServer
			// Register reflection service on gRPC server.
			reflection.Register(grpcServer)
			if err := grpcServer.Serve(grpcListener); err != nil {
				grpcLogger.Errorf("failed to serve: %v", err)
				server.Stop()
				os.Exit(1)
				return
			}
		}()
	}
	<-parentContext.Done()
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
