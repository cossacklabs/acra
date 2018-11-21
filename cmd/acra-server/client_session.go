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

package main

import (
	"context"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/network"
	"go.opencensus.io/trace"
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/mysql"
	"github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"io"
)

// ClientSession handles connection between database and AcraServer.
type ClientSession struct {
	config         *Config
	keystorage     keystore.KeyStore
	connection     net.Conn
	connectionToDb net.Conn
	Server         *SServer
	ctx            context.Context
	logger         *log.Entry
}

// NewClientSession creates new ClientSession object.
func NewClientSession(ctx context.Context, keystorage keystore.KeyStore, config *Config, connection net.Conn) (*ClientSession, error) {
	return &ClientSession{connection: connection, keystorage: keystorage, config: config, ctx: ctx, logger: logging.NewLoggerWithTrace(ctx)}, nil
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
func (clientSession *ClientSession) HandleClientConnection(clientID []byte, decryptorImpl base.Decryptor) {
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
	var pgProxy *postgresql.PgProxy
	if clientSession.config.UseMySQL() {
		clientSession.logger.Debugln("MySQL connection")
		trace.FromContext(clientSession.ctx).AddAttributes(trace.StringAttribute("db.type", "mysql"))
		handler, err := mysql.NewMysqlHandler(clientSession.ctx, clientID, decryptorImpl, clientSession.connectionToDb, clientSession.connection, clientSession.config.GetTLSConfig(), clientSession.config.censor)
		if err != nil {
			clientSession.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitDecryptor).
				Errorln("Can't initialize mysql handler")
			return
		}
		dataEncryptor, err := encryptor.NewAcrawriterDataEncryptor(clientSession.Server.keystorage)
		if err != nil {
			clientSession.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDataEncryptorInitialization).
				Errorln("Can't initialize data encryptor to encrypt data in queries")
			return
		}
		queryEncryptor, err := encryptor.NewMysqlQueryEncryptor(clientSession.config.tableSchema, clientID, dataEncryptor)
		if err != nil {
			clientSession.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorEncryptorInitialization).Errorln("Can't initialize query encryptor")
			return
		}
		handler.AddQueryObserver(queryEncryptor)
		go handler.ClientToDbConnector(clientProxyErrorCh)
		go handler.DbToClientConnector(dbProxyErrorCh)
	} else {
		trace.FromContext(clientSession.ctx).AddAttributes(trace.StringAttribute("db.type", "postgresql"))
		pgProxy, err = postgresql.NewPgProxy(clientSession.ctx, clientSession.connection, clientSession.connectionToDb)
		if err != nil {
			clientSession.logger.WithError(err).Errorln("Can't initialize postgresql proxy")
			return
		}
		clientSession.logger.Debugln("PostgreSQL connection")
		go pgProxy.PgProxyClientRequests(clientSession.config.censor, clientSession.connectionToDb, clientSession.connection, clientProxyErrorCh)
		go pgProxy.PgDecryptStream(clientSession.config.censor, decryptorImpl, clientSession.config.GetTLSConfig(), clientSession.connectionToDb, clientSession.connection, dbProxyErrorCh)
	}
	var channelToWait chan error
	const (
		acraDbSide     = "AcraServer<->Database"
		clientAcraSide = "Client/Connector<->Database"
	)
	var interruptSide string
	for {
		select {
		case err = <-dbProxyErrorCh:
			clientSession.logger.Debugln("Stop to proxy Database -> AcraServer")
			interruptSide = acraDbSide
			channelToWait = clientProxyErrorCh
			break
		case err = <-clientProxyErrorCh:
			interruptSide = clientAcraSide
			clientSession.logger.Debugln("Stop to proxy AcraServer -> Client")
			channelToWait = dbProxyErrorCh
			break
		}
		clientSession.logger = clientSession.logger.WithField("interrupt_side", interruptSide)
		if err == io.EOF {
			clientSession.logger.Debugln("EOF connection closed")
		} else if err == nil {
			break
		} else if netErr, ok := err.(net.Error); ok {
			if netErr.Timeout() {
				clientSession.logger.Debugln("Network timeout")
				if clientSession.config.UseMySQL() {
					break
				} else {
					pgProxy.TLSCh <- true
					// in postgresql mode timeout used to stop listening connection in background goroutine
					// and it's normal behaviour
					continue
				}
			}
			clientSession.logger.WithError(netErr).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantHandleSecureSession).
				Errorln("Network error")
		} else if opErr, ok := err.(*net.OpError); ok {
			clientSession.logger.WithError(opErr).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantHandleSecureSession).Errorln("Network error")
		} else {
			clientSession.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantHandleSecureSession).Errorln("Unexpected error")
		}
		break
	}
	clientSession.logger.Infof("Closing client's connection")
	clientSession.close()

	// wait second error from closed second connection
	clientSession.logger.WithError(<-channelToWait).Debugln("Second proxy goroutine stopped")
	clientSession.logger.Infoln("Finished processing client's connection")
}
