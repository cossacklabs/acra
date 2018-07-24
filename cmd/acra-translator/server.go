package main

import (
	"context"
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

type ReaderServer struct {
	config            *AcraTranslatorConfig
	keystorage        keystore.KeyStore
	connectionManager *network.ConnectionManager
	grpcServer        *grpc.Server

	httpDecryptor *http_api.HTTPConnectionsDecryptor

	waitTimeout time.Duration

	listenersContextCancel []context.CancelFunc
}

func NewReaderServer(config *AcraTranslatorConfig, keystorage keystore.KeyStore, waitTimeout time.Duration) (server *ReaderServer, err error) {
	return &ReaderServer{
		waitTimeout:       waitTimeout,
		config:            config,
		keystorage:        keystorage,
		connectionManager: network.NewConnectionManager(),
	}, nil
}

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
		log.WithError(err).Errorln("Took error on closing available connections")
	}
}

func (server *ReaderServer) listenerContext(parentContext context.Context) context.Context {
	ctx, cancel := context.WithCancel(parentContext)
	server.listenersContextCancel = append(server.listenersContextCancel, cancel)
	return ctx
}

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
		logger.WithError(err).Errorf("Can't start to handle connection string %v", connectionString)
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

			wrappedConnection, clientId, err := server.config.ConnectionWrapper.WrapServer(connection)
			if err != nil {
				logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantWrapConnectionToSS).
					Errorln("Can't wrap new connection")
				if err := connection.Close(); err != nil {
					logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantCloseConnection).
						Errorln("Can't close connection")
				}
				continue
			}
			logger = logger.WithField("client_id", string(clientId))
			logger.Debugln("Pass wrapped connection to processing function")
			logging.SetLoggerToContext(parentContext, logger)

			go func() {
				defer func() {
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

				processingFunc(parentContext, clientId, wrappedConnection)

				if err := server.connectionManager.RemoveConnection(wrappedConnection); err != nil {
					logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPConnection).
						Errorln("Can't remove connection from connection manager")
				}
			}()
		}
	}()
	var outErr error = nil
	select {
	case <-parentContext.Done():
		log.WithError(parentContext.Err()).Debugln("Exit from handling connection string. Close all connections")
	case outErr = <-errCh:
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantAcceptNewHTTPConnection).
			Errorln("Error on accepting new connections")
		server.Stop()
		os.Exit(1)

	}
	return outErr
}

const (
	CONNECTION_TYPE_KEY  = "connection_type"
	HTTP_CONNECTION_TYPE = "http"
	GRPC_CONNECTION_TYPE = "grpc"
)

func (server *ReaderServer) Start(parentContext context.Context) {
	logger := logging.GetLoggerFromContext(parentContext)
	poisonCallbacks := base.NewPoisonCallbackStorage()
	if server.config.DetectPoisonRecords() {
		if server.config.stopOnPoison {
			poisonCallbacks.AddCallback(&base.StopCallback{})
		}
		if server.config.scriptOnPoison != "" {
			poisonCallbacks.AddCallback(base.NewExecuteScriptCallback(server.config.scriptOnPoison))
		}
	}
	decryptorData := &common.TranslatorData{Keystorage: server.keystorage, PoisonRecordCallbacks: poisonCallbacks, CheckPoisonRecords: server.config.detectPoisonRecords}
	if server.config.incomingConnectionHTTPString != "" {
		go func() {
			httpContext := logging.SetLoggerToContext(parentContext, logger.WithField(CONNECTION_TYPE_KEY, HTTP_CONNECTION_TYPE))
			httpDecryptor, err := http_api.NewHTTPConnectionsDecryptor(decryptorData)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPConnection).
					Errorln("Can't create http decryptor")
			}
			server.httpDecryptor = httpDecryptor
			err = server.HandleConnectionString(httpContext, server.config.incomingConnectionHTTPString, server.processHTTPConnection)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPConnection).
					Errorln("Took error on handling http requests")
			}
		}()
	}
	if server.config.incomingConnectionGRPCString != "" {
		go func() {
			grpcLogger := logger.WithField(CONNECTION_TYPE_KEY, GRPC_CONNECTION_TYPE)
			logger.WithField("connection_string", server.config.incomingConnectionGRPCString).Infof("Start process grpc requests")
			secureSessionListener, err := network.NewSecureSessionListener(server.config.incomingConnectionGRPCString, server.keystorage)
			if err != nil {
				grpcLogger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleGRPCConnection).
					Errorln("Can't create secure session listener")
				return
			}
			grpcServer := grpc.NewServer()
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
			if err := grpcServer.Serve(secureSessionListener); err != nil {
				grpcLogger.Errorf("failed to serve: %v", err)
				server.Stop()
				os.Exit(1)
				return
			}
		}()
	}
	<-parentContext.Done()
}

type ProcessingFunc func(context.Context, []byte, net.Conn)

func (server *ReaderServer) processHTTPConnection(parentContext context.Context, clientId []byte, connection net.Conn) {
	// processing HTTP connection
	logger := logging.GetLoggerFromContext(parentContext)
	httpLogger := logger.WithField(CONNECTION_TYPE_KEY, HTTP_CONNECTION_TYPE)
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

	response := server.httpDecryptor.ParseRequestPrepareResponse(logger, request, clientId)
	server.httpDecryptor.SendResponse(logger, response, connection)
}
