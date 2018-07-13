package main

import (
	"context"
	"net"
	"time"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	log "github.com/sirupsen/logrus"
	"net/http"
	"bufio"
	"github.com/cossacklabs/acra/cmd/acra-reader/http-api"
)

type ReaderServer struct {
	config            *AcraReaderConfig
	keystorage        keystore.KeyStore
	connectionManager *network.ConnectionManager

	httpDecryptor *http_api.HTTPConnectionsDecryptor

	waitTimeout time.Duration

	listenersContextCancel []context.CancelFunc
}

func NewReaderServer(config *AcraReaderConfig, keystorage keystore.KeyStore, waitTimeout time.Duration) (server *ReaderServer, err error) {
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
	if server.connectionManager.Counter != 0 {
		log.Infof("Wait ending current connections (%v)", server.connectionManager.Counter)
		// wait existing connections to end request
		<-time.NewTimer(server.waitTimeout).C
	}

	log.Infof("Stop all connections that not closed (%v)", server.connectionManager.Counter)
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
		logger.WithError(err).Errorln("Can't start to handle connection string")
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
				logger.WithError(err).Errorln("Can't wrap new connection")
				if err := connection.Close(); err != nil {
					logger.WithError(err).Errorln("Can't close connection")
				}
				continue
			}
			logger = logger.WithField("client_id", clientId)
			logger.Debugln("Pass wrapped connection to processing function")
			logging.SetLoggerToContext(parentContext, logger)

			go func() {
				if err := server.connectionManager.AddConnection(wrappedConnection); err != nil {
					logger.WithError(err).Errorln("can't add connection to connection manager")
					return
				}
				processingFunc(parentContext, clientId, wrappedConnection)
				if err := server.connectionManager.RemoveConnection(wrappedConnection); err != nil {
					logger.WithError(err).Errorln("can't remove connection from connection manager")
				}
			}()
		}
	}()
	var outErr error = nil
	select {
	case <-parentContext.Done():
		log.WithError(parentContext.Err()).Debugln("Exit from handling connection string. Close all connections")
	case outErr = <-errCh:
		log.WithError(err).Errorln("error on accepting new connections")

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
	if server.config.incomingConnectionHTTPString != "" {
		go func() {
			httpContext := logging.SetLoggerToContext(parentContext, logger.WithField(CONNECTION_TYPE_KEY, HTTP_CONNECTION_TYPE))
			httpDecryptor, err := http_api.NewHTTPConnectionsDecryptor(server.keystorage)
			if err != nil {
				log.WithError(err).Errorln("Can't create http decryptor")
			}
			server.httpDecryptor = httpDecryptor
			err = server.HandleConnectionString(httpContext, server.config.incomingConnectionHTTPString, server.processHTTPConnection)
			if err != nil {
				log.WithError(err).Errorln("Took error on handling http requests")
			}
		}()
	}
	if server.config.incomingConnectionGRPCString != "" {
		go func() {
			grpcContext := logging.SetLoggerToContext(parentContext, logger.WithField(CONNECTION_TYPE_KEY, GRPC_CONNECTION_TYPE))
			err := server.HandleConnectionString(grpcContext, server.config.incomingConnectionGRPCString, server.processGRPCConnection)
			if err != nil {
				log.WithError(err).Errorln("Took error on handling grpc requests")
			}
		}()
	}
	<-parentContext.Done()
}

type ProcessingFunc func(context.Context, []byte, net.Conn)

func (server *ReaderServer) processGRPCConnection(parentContext context.Context, clientId []byte, connection net.Conn) {
	// processing GRPC connection
	logger := logging.GetLoggerFromContext(parentContext)
	logger.Debugln("grpc handler")
}


func (server *ReaderServer) processHTTPConnection(parentContext context.Context, clientId []byte, connection net.Conn) {
	// processing HTTP connection
	logger := logging.GetLoggerFromContext(parentContext)
	httpLogger := logger.WithField(CONNECTION_TYPE_KEY, HTTP_CONNECTION_TYPE)
	httpLogger.Debugln("HTTP handler")

	reader := bufio.NewReader(connection)
	request, err := http.ReadRequest(reader)

	// TODO: handle keep alive

	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantHandleHTTPRequest).
			Warningln("Got new HTTP request, but can't read it")
		server.httpDecryptor.SendResponseAndCloseConnection(logger,
			server.httpDecryptor.EmptyResponseWithStatus(request, http.StatusBadRequest), connection)
		return
	}

	response := server.httpDecryptor.ParseRequestPrepareResponse(logger, request, clientId)
	server.httpDecryptor.SendResponseAndCloseConnection(logger, response, connection)
}