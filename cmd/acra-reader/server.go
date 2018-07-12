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
	"io/ioutil"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/acra/utils"
	"strings"
	"os"
	"bytes"
	"encoding/binary"
)

type ReaderServer struct {
	config            *AcraReaderConfig
	keystorage        keystore.KeyStore
	connectionManager *network.ConnectionManager

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
	logger.Debugln("HTTP handler")

	reader := bufio.NewReader(connection)
	request, err := http.ReadRequest(reader)

	// TODO: handle keep alive

	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantHandleHTTPRequest).
			Warningln("Got new HTTP request, but can't read it")
		server.sendResponseAndCloseConnection(logger, emptyResponseWithStatus(request, http.StatusBadRequest), connection)
		return
	}

	response := server.parseRequestPrepareResponse(logger, request, clientId)
	server.sendResponseAndCloseConnection(logger, response, connection)
}


func (server *ReaderServer) sendResponseAndCloseConnection(logger *log.Entry, response *http.Response, connection net.Conn) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, response)

	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantReturnResponse).
			Warningln("Can't convert response to binary")
	} else {
		_, err = connection.Write(buf.Bytes())
		if err != nil {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantReturnResponse).
				Warningln("Can't write response to HTTP request")
		}
	}

	err = connection.Close()
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantCloseConnection).
			Warningln("Can't close connection of HTTP request")
	}
}


func (server *ReaderServer) parseRequestPrepareResponse(logger *log.Entry, request *http.Request, clientId []byte) *http.Response {
	if request == nil || request.URL == nil {
		return emptyResponseWithStatus(request, http.StatusBadRequest)
	}

	log.Debugf("Incoming API request to %v", request.URL.Path)

	if request.Method != http.MethodPost {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderMethodNotAllowed).
			Warningf("HTTP method is not allowed, expected POST, got %s", request.Method)
		return emptyResponseWithStatus(request, http.StatusMethodNotAllowed)
	}

	// /v1/decrypt
	// /, v1, decrypt
	pathParts := strings.Split(request.URL.Path, string(os.PathSeparator))
	if len(pathParts) != 3 {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderMalformedURL).
			Warningf("Malformed URL, expected /<version>/<endpoint>, got %s", request.URL.Path)
		return emptyResponseWithStatus(request, http.StatusBadRequest)
	}

	version := pathParts[1] // v1
	if version != "v1" {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderVersionNotSupported).
			Warningf("HTTP request version is not supported: expected v1, got %s", version)
		return emptyResponseWithStatus(request, http.StatusBadRequest)
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

		if zoneId == nil && clientId == nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantZoneIdMissing).
				Warningln("HTTP request doesn't have a ZoneId, connection doesn't have a ClientId, expected to get one of them. Send ZoneId in request URL")
			return emptyResponseWithStatus(request, http.StatusBadRequest)
		}

		if request.Body == nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantParseRequestBody).
				Warningln("HTTP request doesn't have a body, expected to get AcraStruct")
			return emptyResponseWithStatus(request, http.StatusBadRequest)
		}

		acraStruct, err := ioutil.ReadAll(request.Body)
		defer request.Body.Close()

		if acraStruct == nil || err != nil {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantParseRequestBody).
				Warningln("HTTP request doesn't have a body, expected to get AcraStruct")
			return emptyResponseWithStatus(request, http.StatusBadRequest)
		}

		decryptedStruct, err := server.decryptAcraStruct(acraStruct, zoneId, clientId)

		if err != nil {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantDecryptAcraStruct).
				Warningln("Can't decrypt AcraStruct")
			return emptyResponseWithStatus(request, http.StatusUnprocessableEntity)
		}

		logger.Infof("Decrypted AcraStruct for client_id=%s zone_id=%s", clientId, zoneId)

		response := emptyResponseWithStatus(request, http.StatusOK)
		response.Header.Set("Content-Type", "application/octet-stream")
		response.Body = ioutil.NopCloser(bytes.NewBuffer(decryptedStruct))
		response.ContentLength = int64(len(decryptedStruct))
		return response
	default:
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderEndpointNotSupported).
			Warningln("HTTP endpoint not supported")
	}

	return emptyResponseWithStatus(request, http.StatusBadRequest)
}

func (server *ReaderServer)decryptAcraStruct(acraStruct []byte, zoneId []byte, clientId []byte) ([]byte, error) {
	var err error
	var privateKey *keys.PrivateKey

	if zoneId != nil {
		privateKey, err = server.keystorage.GetZonePrivateKey(zoneId)
	} else {
		privateKey, err = server.keystorage.GetServerDecryptionPrivateKey(clientId)
	}

	if err != nil {
		return nil, err
	}

	// decrypt
	decryptedStruct, err := base.DecryptAcrastruct(acraStruct, privateKey, zoneId)
	// zeroing private key
	utils.FillSlice(byte(0), privateKey.Value)

	if err != nil {
		return nil, err
	}

	return decryptedStruct, nil
}

func emptyResponseWithStatus(request *http.Request, status int) *http.Response {
	return &http.Response{
		Status:        http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       request,
		ContentLength: -1,
		Header:        http.Header{},
	}
}
