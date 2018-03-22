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

	"github.com/cossacklabs/acra/decryptor/mysql"
	"github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/network"
	log "github.com/sirupsen/logrus"

	"io"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
)

type ClientSession struct {
	config         *Config
	keystorage     keystore.KeyStore
	connection     net.Conn
	connectionToDb net.Conn
	Server *SServer
}

func NewClientSession(keystorage keystore.KeyStore, config *Config, connection net.Conn) (*ClientSession, error) {
	return &ClientSession{connection: connection, keystorage: keystorage, config: config}, nil
}

func (clientSession *ClientSession) ConnectToDb() error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%v:%v", clientSession.config.GetDBHost(), clientSession.config.GetDBPort()))
	if err != nil {
		return err
	}
	clientSession.connectionToDb = conn
	return nil
}

func (clientSession *ClientSession) close() {
	log.Debugln("close acraproxy connection")

	err := clientSession.connection.Close()
	if err != nil {
		log.Warningf("%v", utils.ErrorMessage("error with closing connection to acraproxy", err))
	}
	log.Debugln("close db connection")
	err = clientSession.connectionToDb.Close()
	if err != nil {
		log.Warningf("%v", utils.ErrorMessage("error with closing connection to db", err))
	}
	log.Debugln("all connections closed")
}

/* proxy connections from client to db and decrypt responses from db to client
if any error occurred than end processing
*/
func (clientSession *ClientSession) HandleSecureSession(decryptorImpl base.Decryptor) {
	innerErrorChannel := make(chan error, 2)

	err := clientSession.ConnectToDb()
	if err != nil {
		log.WithError(err).Errorln("can't connect to db")
		log.Debugln("close connection with acraproxy")
		err = clientSession.connection.Close()
		if err != nil {
			log.Warningf("%v", utils.ErrorMessage("error with closing connection to acraproxy", err))
		}
		return
	}
	pgDecryptorConfig, err := postgresql.NewPgDecryptorConfig(clientSession.config.GetTLSServerKeyPath(), clientSession.config.GetTLSServerCertPath())
	if err != nil {
		log.WithError(err).Errorln("can't initialize config for postgresql decryptor")
		err = clientSession.connection.Close()
		if err != nil {
			log.Warningf("%v", utils.ErrorMessage("error with closing connection to acraproxy", err))
		}
		return
	}
	if clientSession.config.UseMySQL() {
		log.Debugln("MySQL connection")
		handler, err := mysql.NewMysqlHandler(decryptorImpl)
		if err != nil {
			log.WithError(err).Errorln("can't initialize mysql handler")
			return
		}
		//go handler.MysqlDecryptStream(decryptorImpl, clientSession.connectionToDb, clientSession.connection, innerErrorChannel)
		go handler.ClientToDbProxy(decryptorImpl, clientSession.connectionToDb, clientSession.connection, innerErrorChannel)
		go handler.DbToClientProxy(decryptorImpl, clientSession.connectionToDb, clientSession.connection, innerErrorChannel)
	} else {
		log.Debugln("PostgreSQL connection")
		go network.Proxy(clientSession.connection, clientSession.connectionToDb, innerErrorChannel)
		go postgresql.PgDecryptStream(decryptorImpl, pgDecryptorConfig, clientSession.connectionToDb, clientSession.connection, innerErrorChannel)
	}
	for {
		err = <-innerErrorChannel

		if err == io.EOF {
			log.Debugln("EOF connection closed")
		} else if netErr, ok := err.(net.Error); ok {
			if netErr.Timeout() {
				log.Debugln("network timeout")
				if clientSession.config.UseMySQL() {
					break
				} else {
					// in postgresql mode timeout used to stop listening connection in background goroutine
					// and it's normal behaviour
					continue
				}
			}
			log.WithError(netErr).Errorln("network error")
		} else if opErr, ok := err.(*net.OpError); ok {
			log.WithError(opErr).Errorln("network error")
		} else {
			log.WithError(err).Errorln("unexpected error")
		}
		break
	}
	clientSession.close()
	// wait second error from closed second connection
	<-innerErrorChannel
}
