// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"fmt"
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
}

// NewClientSession creates new ClientSession object.
func NewClientSession(keystorage keystore.KeyStore, config *Config, connection net.Conn) (*ClientSession, error) {
	return &ClientSession{connection: connection, keystorage: keystorage, config: config}, nil
}

// ConnectToDb connects to the database via tcp using Host and Port from config.
func (clientSession *ClientSession) ConnectToDb() error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%v:%v", clientSession.config.GetDBHost(), clientSession.config.GetDBPort()))
	if err != nil {
		return err
	}
	clientSession.connectionToDb = conn
	return nil
}

func (clientSession *ClientSession) close() {
	log.Debugln("Close acra-connector connection")

	err := clientSession.connection.Close()
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnectionToService).
			Errorln("Error with closing connection to acra-connector")
	}
	log.Debugln("Close db connection")
	err = clientSession.connectionToDb.Close()
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnectionDB).
			Errorln("Error with closing connection to db")
	}
	log.Debugln("All connections closed")
}

// HandleClientConnection handles Acra-connector connections from client to db and decrypt responses from db to client.
// If any error occurred – ends processing.
func (clientSession *ClientSession) HandleClientConnection(clientId []byte, decryptorImpl base.Decryptor) {
	log.Infof("Handle client's connection")
	clientProxyErrorCh := make(chan error, 1)
	dbProxyErrorCh := make(chan error, 1)

	log.Debugf("Connecting to db")
	err := clientSession.ConnectToDb()
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantConnectToDB).
			Errorln("Can't connect to db")

		log.Debugln("Close connection with acra-connector")
		err = clientSession.connection.Close()
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnectionToService).
				Errorln("Error with closing connection to acra-connector")
		}
		return
	}
	var pgProxy *postgresql.PgProxy
	if clientSession.config.UseMySQL() {
		log.Debugln("MySQL connection")
		handler, err := mysql.NewMysqlHandler(clientId, decryptorImpl, clientSession.connectionToDb, clientSession.connection, clientSession.config.GetTLSConfig(), clientSession.config.censor)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitDecryptor).
				Errorln("Can't initialize mysql handler")
			return
		}
		go handler.ClientToDbConnector(clientProxyErrorCh)
		go handler.DbToClientConnector(dbProxyErrorCh)
	} else {
		pgProxy, err = postgresql.NewPgProxy(clientSession.connection, clientSession.connectionToDb)
		if err != nil {
			log.WithError(err).Errorln("can't initialize postgresql proxy")
			return
		}
		log.Debugln("PostgreSQL connection")
		go pgProxy.PgProxyClientRequests(clientSession.config.censor, clientSession.connectionToDb, clientSession.connection, clientProxyErrorCh)
		go pgProxy.PgDecryptStream(clientSession.config.censor, decryptorImpl, clientSession.config.GetTLSConfig(), clientSession.connectionToDb, clientSession.connection, dbProxyErrorCh)
	}
	var channelToWait chan error
	for {
		select {
		case err = <-dbProxyErrorCh:
			log.WithError(err).Debugln("error from db proxy")
			channelToWait = clientProxyErrorCh
			break
		case err = <-clientProxyErrorCh:
			channelToWait = dbProxyErrorCh
			log.WithError(err).Debugln("error from client proxy")
			break
		}

		if err == io.EOF {
			log.Debugln("EOF connection closed")
		} else if netErr, ok := err.(net.Error); ok {
			if netErr.Timeout() {
				log.Debugln("Network timeout")
				if clientSession.config.UseMySQL() {
					break
				} else {
					pgProxy.TlsCh <- true
					// in postgresql mode timeout used to stop listening connection in background goroutine
					// and it's normal behaviour
					continue
				}
			}
			log.WithError(netErr).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantHandleSecureSession).
				Errorln("Network error")
		} else if opErr, ok := err.(*net.OpError); ok {
			log.WithError(opErr).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantHandleSecureSession).Errorln("Network error")
		} else {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantHandleSecureSession).Errorln("Unexpected error")
		}
		break
	}
	log.Infof("Closing client's connection")
	clientSession.close()

	// wait second error from closed second connection
	log.WithError(<-channelToWait).Debugln("second proxy goroutine stopped")
	log.Infoln("Finished processing client's connection")
}
