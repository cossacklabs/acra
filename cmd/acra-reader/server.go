package main

import (
	"context"
	"net"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	log "github.com/sirupsen/logrus"
)

type ReaderServer struct {
	config     *AcraReaderConfig
	keystorage keystore.KeyStore
}

func NewReaderServer(config *AcraReaderConfig, keystorage keystore.KeyStore) (server *ReaderServer, err error) {
	return &ReaderServer{
		config:     config,
		keystorage: keystorage,
	}, nil
}

func (server *ReaderServer) HandleConnectionString(parentContext context.Context, connectionString string, processingFunc ProcessingFunc) error {
	logger := logging.GetLoggerFromContext(parentContext)
	if logger == nil {
		logger = log.NewEntry(log.StandardLogger())
	}
	logger = log.WithField("connection_string", connectionString)

	errCh := make(chan error)
	// start accept new connections from connectionString
	connectionChannel, err := AcceptConnections(parentContext, connectionString, errCh)
	if err != nil {
		logger.WithError(err).Errorln("Can't start to handle connection string")
		return err
	}
	// use to send close packets to all unclosed connections at end
	connectionManager := network.NewConnectionManager()
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
				connectionManager.AddConnection(wrappedConnection)
				processingFunc(parentContext, clientId, wrappedConnection)
				connectionManager.RemoveConnection(wrappedConnection)
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

	if err := connectionManager.CloseConnections(); err != nil {
		logger.WithError(err).Errorln("Took error on closing available connections")
		if outErr == nil {
			outErr = err
		}
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
			err := server.HandleConnectionString(httpContext, server.config.incomingConnectionHTTPString, server.processHTTPConnection)
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
	logger.Debugln("http handler")
}
