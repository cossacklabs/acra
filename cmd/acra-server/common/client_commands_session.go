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
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
)

// HTTP 500 response
const (
	Response500Error = "HTTP/1.1 500 Server error\r\n\r\n\r\n\r\n"
)

// ClientCommandsSession handles Secure Session for client commands API
type ClientCommandsSession struct {
	ctx        context.Context
	server     *SServer
	config     *Config
	keystore   keystore.ServerKeyStore
	connection net.Conn
}

// NewClientCommandsSession returns new ClientCommandsSession
func NewClientCommandsSession(ctx context.Context, server *SServer, config *Config, connection net.Conn) (*ClientCommandsSession, error) {
	return &ClientCommandsSession{ctx: ctx, server: server, config: config, keystore: config.GetKeyStore(), connection: connection}, nil
}

// ConnectToDb should not be called, because command session must not connect to any DB
func (clientSession *ClientCommandsSession) ConnectToDb() error {
	return errors.New("command session must not connect to any DB")
}

func (clientSession *ClientCommandsSession) close() {
	log.Debugln("Close acra-connector connection")
	err := clientSession.connection.Close()
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnection).
			Errorln("Error during closing connection to acra-connector")
	}
	log.Debugln("All connections closed")
}

func (clientSession *ClientCommandsSession) generateZoneKeys() ([]byte, []byte, error) {
	id, publicKey, err := clientSession.keystore.GenerateZoneKey()
	if err != nil {
		return nil, nil, err
	}
	if err = clientSession.keystore.GenerateZoneIDSymmetricKey(id); err != nil {
		return nil, nil, err
	}
	return id, publicKey, nil
}

// HandleSession gets, parses and executes each client HTTP request, writes response to the connection
func (clientSession *ClientCommandsSession) HandleSession() {
	defer func() {
		if recMsg := recover(); recMsg != nil {
			log.WithField("error", recMsg).WithFields(
				log.Fields{"connection_type": "http_api"}).
				Errorln("Panic in connection processing, close connection")
			clientSession.close()
		}
	}()
	_, requestSpan := trace.StartSpan(clientSession.ctx, "HandleSession")
	defer requestSpan.End()

	logger := logging.NewLoggerWithTrace(clientSession.ctx)
	reader := bufio.NewReader(clientSession.connection)
	req, err := http.ReadRequest(reader)
	// req = clientSession.connection.Write(*http.ResponseWriter)
	if err != nil {

		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			Warningln("Got new command request, but can't read it")
		clientSession.close()
		return
	}
	response := "HTTP/1.1 404 Not Found\r\n\r\nincorrect request\r\n\r\n"

	logger.Debugf("Incoming API request to %v", req.URL.Path)

	requestSpan.AddAttributes(trace.StringAttribute("http.url", req.URL.Path))

	switch req.URL.Path {
	case "/getNewZone":
		logger.Debugln("Got /getNewZone request")
		id, publicKey, err := clientSession.generateZoneKeys()
		if err != nil {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorHTTPAPICantGenerateZone).Errorln("Can't generate zone key")
		} else {
			zoneData, err := zone.DataToJSON(id, &keys.PublicKey{Value: publicKey})
			if err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorHTTPAPICantGenerateZone).WithError(err).Errorln("Can't create json with zone key")
			} else {
				logger.Debugln("Handled request correctly")
				response = fmt.Sprintf("HTTP/1.1 200 OK Found\r\n\r\n%s\r\n\r\n", string(zoneData))
			}
		}
	case "/resetKeyStorage":
		logger.Debugln("Got /resetKeyStorage request")
		clientSession.keystore.Reset()
		response = "HTTP/1.1 200 OK Found\r\n\r\n"
		logger.Debugln("Cleared key storage cache")
	default:
		requestSpan.AddAttributes(trace.StringAttribute("http.url", "undefined"))
	}

	_, err = clientSession.connection.Write([]byte(response))
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).Errorln("Can't send data with secure session to acra-connector")
		return
	}
	clientSession.close()
}

// AcraAPIServer handles all HTTP api logic
type AcraAPIServer struct {
	ctx        context.Context
	server     *SServer
	engine     *gin.Engine
	httpServer *http.Server
}

// NewAcraAPIServer creates new AcraAPIServer
func NewAcraAPIServer(server *SServer) AcraAPIServer {
	gin.SetMode(gin.ReleaseMode)
	// TODO: change to gin.New and configure logger
	engine := gin.Default()
	engine.HandleMethodNotAllowed = true

	apiServer := AcraAPIServer{
		ctx:        context.Background(),
		server:     server,
		engine:     engine,
		httpServer: nil,
	}

	apiServer.engine.GET("/getNewZone", apiServer.getNewZone)
	apiServer.engine.GET("/resetKeyStorage", apiServer.resetKeyStorage)

	httpServer := &http.Server{
		Handler:      engine,
		ReadTimeout:  network.DefaultNetworkTimeout,
		WriteTimeout: network.DefaultNetworkTimeout,
	}

	apiServer.httpServer = httpServer

	return apiServer
}

// Start the server. Blocking operation
func (apiServer *AcraAPIServer) Start(listener net.Listener) error {
	go func() {
		<-apiServer.ctx.Done()
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(network.DefaultNetworkTimeout))
		defer cancel()
		if err := apiServer.httpServer.Shutdown(ctx); err != nil {
			log.WithError(err).Errorln("Can't shutdown API server")
			if err := apiServer.httpServer.Close(); err != nil {
				log.WithError(err).Errorln("Can't close API server")
			}
		}
	}()
	return apiServer.httpServer.Serve(listener)
}

func (apiServer *AcraAPIServer) getNewZone(ctx *gin.Context) {
	ctx.String(200, "TODO")
}

func (apiServer *AcraAPIServer) resetKeyStorage(ctx *gin.Context) {
	ctx.String(200, "TODO")
}
