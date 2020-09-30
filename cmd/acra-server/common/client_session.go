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
	"io"
	"net"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	log "github.com/sirupsen/logrus"
)

// ClientSession handles connection between database and AcraServer.
type ClientSession struct {
	config         *Config
	connection     net.Conn
	connectionToDb net.Conn
	ctx            context.Context
	logger         *log.Entry
}

// NewClientSession creates new ClientSession object.
func NewClientSession(ctx context.Context, config *Config, connection net.Conn) (*ClientSession, error) {
	return &ClientSession{connection: connection, config: config, ctx: ctx, logger: logging.GetLoggerFromContext(ctx)}, nil
}

// ConnectToDb connects to the database via tcp using Host and Port from config.
func (clientSession *ClientSession) ConnectToDb() error {
	conn, err := network.Dial(network.BuildConnectionString("tcp", clientSession.config.GetDBHost(), clientSession.config.GetDBPort(), ""))
	if err != nil {
		return err
	}
	clientSession.connectionToDb = conn
	return nil
}

func (clientSession *ClientSession) close() {
	clientSession.logger.Debugln("Close acra-connector connection")

	err := clientSession.connection.Close()
	if err != nil {
		clientSession.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnectionToService).
			Errorln("Error with closing connection to acra-connector")
	}
	clientSession.logger.Debugln("Close db connection")
	err = clientSession.connectionToDb.Close()
	if err != nil {
		clientSession.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnectionDB).
			Errorln("Error with closing connection to db")
	}
	clientSession.logger.Debugln("All connections closed")
}

// HandleClientConnection handles Acra-connector connections from client to db and decrypt responses from db to client.
// If any error occurred – ends processing.
func (clientSession *ClientSession) HandleClientConnection(clientID []byte, proxyFactory base.ProxyFactory) {
	clientSession.logger.Infof("Handle client's connection")
	clientProxyErrorCh := make(chan error, 1)
	dbProxyErrorCh := make(chan error, 1)

	clientSession.logger.Debugf("Connecting to db")
	err := clientSession.ConnectToDb()
	if err != nil {
		clientSession.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantConnectToDB).
			Errorln("Can't connect to db")

		clientSession.logger.Debugln("Close connection with acra-connector")
		err = clientSession.connection.Close()
		if err != nil {
			clientSession.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnectionToService).
				Errorln("Error with closing connection to acra-connector")
		}
		return
	}

	if err != nil {
		clientSession.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDataEncryptorInitialization).
			Errorln("Can't initialize data encryptor to encrypt data in queries")
		return
	}
	proxy, err := proxyFactory.New(clientSession.ctx, clientID, clientSession.connectionToDb, clientSession.connection)
	if err != nil {
		clientSession.logger.WithError(err).Errorln("Can't create new proxy for connection")
		return
	}
	go proxy.ProxyClientConnection(clientProxyErrorCh)
	go proxy.ProxyDatabaseConnection(dbProxyErrorCh)

	var channelToWait chan error
	const (
		acraDbSide     = "AcraServer<->Database"
		clientAcraSide = "Client/Connector<->Database"
	)
	var interruptSide string

	select {
	case err = <-dbProxyErrorCh:
		clientSession.logger.Debugln("Stop to proxy Database -> AcraServer")
		interruptSide = acraDbSide
		channelToWait = clientProxyErrorCh
	case err = <-clientProxyErrorCh:
		interruptSide = clientAcraSide
		clientSession.logger.Debugln("Stop to proxy AcraServer -> Client")
		channelToWait = dbProxyErrorCh
	}
	clientSession.logger = clientSession.logger.WithField("interrupt_side", interruptSide)
	if err == io.EOF {
		clientSession.logger.Debugln("EOF connection closed")
	} else if err == nil {
		clientSession.logger.Debugln("Err == nil from proxy goroutine")
	} else if netErr, ok := err.(net.Error); ok {
		clientSession.logger.WithError(netErr).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneralConnectionProcessing).
			Errorln("Network error")
	} else if opErr, ok := err.(*net.OpError); ok {
		clientSession.logger.WithError(opErr).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneralConnectionProcessing).Errorln("Network error")
	} else {
		clientSession.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneralConnectionProcessing).Errorln("Unexpected error")
	}

	clientSession.logger.Infof("Closing client's connection")
	clientSession.close()

	// wait second error from closed second connection
	clientSession.logger.WithError(<-channelToWait).Debugln("Second proxy goroutine stopped")
	clientSession.logger.Infoln("Finished processing client's connection")
}
