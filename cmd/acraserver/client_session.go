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
	"github.com/cossacklabs/acra/network"
	"log"
	"net"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/session"
	"io"
)

type ClientSession struct {
	session        *session.SecureSession
	config         *Config
	keystorage     keystore.KeyStore
	connection     net.Conn
	connectionToDb net.Conn
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
	log.Println("Debug: close acraproxy connection")

	err := clientSession.connection.Close()
	if err != nil {
		log.Printf("Warning: %v\n", utils.ErrorMessage("error with closing connection to acraproxy", err))
	}
	log.Println("Debug: close db connection")
	err = clientSession.connectionToDb.Close()
	if err != nil {
		log.Printf("Warning: %v\n", utils.ErrorMessage("error with closing connection to db", err))
	}
	log.Println("Debug: all connections closed")
}

/* proxy connections from client to db and decrypt responses from db to client
if any error occurred than end processing
*/
func (clientSession *ClientSession) HandleSecureSession(decryptorImpl base.Decryptor) {
	innerErrorChannel := make(chan error, 2)

	err := clientSession.ConnectToDb()
	if err != nil {
		log.Printf("Error: %v\n", utils.ErrorMessage("can't connect to db", err))
		log.Println("Debug: close connection with acraproxy")
		err = clientSession.connection.Close()
		if err != nil {
			log.Printf("Warning: %v\n", utils.ErrorMessage("error with closing connection to acraproxy", err))
		}
		return
	}

	go network.Proxy(clientSession.connection, clientSession.connectionToDb, innerErrorChannel)
	//go clientSession.proxyConnections(innerErrorChannel)

	go postgresql.PgDecryptStream(decryptorImpl, clientSession.connectionToDb, clientSession.connection, innerErrorChannel)
	for {
		err = <-innerErrorChannel

		if err == io.EOF {
			log.Println("Debug: EOF connection closed")
		} else if netErr, ok := err.(net.Error); ok {
			if netErr.Timeout() {
				log.Println("Debug: network timeout")
				continue
			}
			log.Printf("Error: %v\n", utils.ErrorMessage("network error", netErr))
		} else if opErr, ok := err.(*net.OpError); ok {
			log.Printf("Error: %v\n", utils.ErrorMessage("network error", opErr))
		} else {
			fmt.Printf("Error: %v\n", utils.ErrorMessage("unexpected error", err))
		}
		break
	}
	clientSession.close()
	// wait second error from closed second connection
	<-innerErrorChannel
}
