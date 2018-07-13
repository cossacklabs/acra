package main

import (
	"context"
	"net"
	"time"

	"bufio"
	"bytes"
	"encoding/binary"
	"github.com/cossacklabs/acra/cmd/acra-reader/api"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type ReaderServer struct {
	config            *AcraReaderConfig
	keystorage        keystore.KeyStore
	connectionManager *network.ConnectionManager
	grpcServer        *grpc.Server

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
	// non block stop
	go server.grpcServer.GracefulStop()
	if server.connectionManager.Counter != 0 {
		log.Infof("Wait ending current connections (%v)", server.connectionManager.Counter)
		// wait existing connections to end request
		<-time.NewTimer(server.waitTimeout).C
	}

	log.Infof("Stop all connections that not closed (%v)", server.connectionManager.Counter)
	// force stop of grpc server
	server.grpcServer.Stop()
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
			err := server.HandleConnectionString(httpContext, server.config.incomingConnectionHTTPString, server.processHTTPConnection)
			if err != nil {
				log.WithError(err).Errorln("Took error on handling http requests")
			}
		}()
	}
	if server.config.incomingConnectionGRPCString != "" {
		go func() {
			grpcLogger := logger.WithField(CONNECTION_TYPE_KEY, GRPC_CONNECTION_TYPE)
			secureSessionListener, err := network.NewSecureSessionListener(server.config.incomingConnectionGRPCString, server.keystorage)
			if err != nil {
				grpcLogger.WithError(err).Errorln("Can't create secure sesson listener")
				return
			}
			grpcServer := grpc.NewServer()
			service, err := api.NewDecryptGRPCService(server.keystorage)
			if err != nil {
				grpcLogger.WithError(err).Errorln("Can't create grpc service")
				return
			}
			api.RegisterReaderServer(grpcServer, service)
			server.grpcServer = grpcServer
			// Register reflection service on gRPC server.
			reflection.Register(grpcServer)
			if err := grpcServer.Serve(secureSessionListener); err != nil {
				grpcLogger.Errorf("failed to serve: %v", err)
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
	logger.Debugln("http handler")

	reader := bufio.NewReader(connection)
	request, err := http.ReadRequest(reader)
	response := http.Response{
		Status:        "200 OK",
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       request,
		ContentLength: -1,
		Header:        http.Header{},
	}

	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantHandleHTTPRequest).
			Warningln("Got new HTTP request, but can't read it")
		response.StatusCode = http.StatusBadRequest
		closeConnectionAndSendResponse(logger, response, connection)
		return
	}

	log.Debugf("Incoming API request to %v", request.URL.Path)

	// TODO: handle keep alive

	if request.Method != http.MethodPost {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderMethodNotAllowed).
			Warningf("HTTP method is not allowed, expected /POST, got %s", request.Method)
		response.StatusCode = http.StatusMethodNotAllowed
		closeConnectionAndSendResponse(logger, response, connection)
		return
	}

	// /v1/decrypt
	// /, v1, decrypt
	pathParts := strings.Split(request.URL.Path, string(os.PathSeparator))
	if len(pathParts) != 3 {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderMalformedURL).
			Warningf("Malformed URL, expected /<version>/<endpoint>, got %s", request.URL.Path)
		response.StatusCode = http.StatusBadRequest
		closeConnectionAndSendResponse(logger, response, connection)
		return
	}

	version := pathParts[1] // v1
	if version != "v1" || err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderVersionNotSupported).
			Warningf("HTTP request version is not supported: expected v1, got %s", version)
		response.StatusCode = http.StatusBadRequest
		closeConnectionAndSendResponse(logger, response, connection)
		return
	}

	endpoint := pathParts[2] // decrypt

	switch endpoint {
	case "decrypt":
		var zoneId []byte = nil

		// optional zone_id
		query, ok := request.URL.Query()["zone_id"]
		if ok && len(query) == 1 {
			zoneId = []byte(query[0])
		}

		acraStruct, err := ioutil.ReadAll(request.Body)
		defer request.Body.Close()

		if err != nil {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantParseRequestBody).
				Warningln("HTTP request doesn't have a body, expected to get AcraStruct")
			response.StatusCode = http.StatusBadRequest
			closeConnectionAndSendResponse(logger, response, connection)
			return
		}

		var privateKey *keys.PrivateKey
		if zoneId != nil {
			privateKey, err = server.keystorage.GetZonePrivateKey(zoneId)
		} else {
			privateKey, err = server.keystorage.GetZonePrivateKey(clientId)
		}

		if err != nil {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantReadPrivateKeyForDecryption).
				Warningln("Can't read Private Key for ZoneId")
			response.StatusCode = http.StatusUnprocessableEntity
			closeConnectionAndSendResponse(logger, response, connection)
			return
		}

		// decrypt
		decryptedStruct, err := base.DecryptAcrastruct(acraStruct, privateKey, zoneId)
		utils.FillSlice(byte(0), privateKey.Value)

		if err != nil {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantDecryptAcraStruct).
				Warningf("Can't decrypt AcraStruct")
			response.StatusCode = http.StatusUnprocessableEntity
			closeConnectionAndSendResponse(logger, response, connection)
			return
		}

		response.Header.Set("Content-Type", "application/octet-stream")
		response.Body = ioutil.NopCloser(bytes.NewBuffer(decryptedStruct))
		response.ContentLength = int64(len(decryptedStruct))

	default:
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderEndpointNotSupported).
			Warningln("HTTP endpoint not supported")
		response.StatusCode = http.StatusBadRequest
	}

	closeConnectionAndSendResponse(logger, response, connection)
}

func closeConnectionAndSendResponse(logger *log.Entry, response http.Response, connection net.Conn) {
	response.Status = http.StatusText(response.StatusCode)

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, response)

	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantReturnResponse).
			Warningln("Can't write response to HTTP request")
	} else {
		connection.Write(buf.Bytes())
	}

	connection.Close()
}
