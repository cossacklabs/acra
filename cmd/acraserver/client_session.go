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
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/cossacklabs/acra/config"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/keystore"
	. "github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/session"
	"io"
)

type ClientSession struct {
	session          *session.SecureSession
	config           *config.Config
	keystorage       keystore.KeyStore
	connection       net.Conn
	connection_to_db net.Conn
}

func (client_session *ClientSession) GetPublicKeyForId(ss *session.SecureSession, id []byte) *keys.PublicKey {

	// try to open file in PUBLIC_KEYS_DIR directory where pub file should be named like <client_id>.pub
	log.Printf("Debug: load client's public key: %v\n", fmt.Sprintf("%v/%v.pub", client_session.config.GetKeysDir(), string(id)))
	key, err := LoadPublicKey(fmt.Sprintf("%v/%v.pub", client_session.config.GetKeysDir(), string(id)))
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage(fmt.Sprintf("can't load public key for id %v", string(id)), err))
	}
	return key
}

func (client_session *ClientSession) StateChanged(ss *session.SecureSession, state int) {}

/* return server's private key for this client_id */
func get_server_private_key(client_id []byte, keys_dir string) (*keys.PrivateKey, error) {
	log.Printf("Debug: load private key: %v\n", fmt.Sprintf("%v/%v_server", keys_dir, string(client_id)))
	return LoadPrivateKey(fmt.Sprintf("%v/%v_server", keys_dir, string(client_id)))
}

func NewClientSession(keystorage keystore.KeyStore, config *config.Config, connection net.Conn) (*ClientSession, error) {

	return &ClientSession{connection: connection, keystorage: keystorage, config: config}, nil
}

func (client_session *ClientSession) ConnectToDb() error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%v:%v", client_session.config.GetDBHost(), client_session.config.GetDBPort()))
	if err != nil {
		return err
	}
	client_session.connection_to_db = conn
	return nil
}

/* read packets from client app wrapped in ss, unwrap them and send to db as is */
func (client_session *ClientSession) proxyConnections(err_ch chan error) {
	for {
		data, err := ReadData(client_session.connection)
		if err != nil {
			err_ch <- err
			return
		}

		decrypted_data, _, err := client_session.session.Unwrap(data)
		if err != nil {
			err_ch <- err
			return
		}

		n, err := client_session.connection_to_db.Write(decrypted_data)
		if err != nil {
			err_ch <- err
			return
		}
		if n != len(decrypted_data) {
			err_ch <- errors.New("sent incorrect bytes count")
			return
		}
	}
}

/* io.Writer implementation where all data wraps to SS and send with length as prefix */
func (client_session *ClientSession) Write(data []byte) (n int, err error) {
	encrypted_data, err := client_session.session.Wrap(data)
	if err != nil {
		return 0, err
	}
	err = SendData(encrypted_data, client_session.connection)
	if err != nil {
		return 0, err
	}
	n = len(data)
	return
}

func (client_session *ClientSession) close() {
	log.Println("Debug: close acraproxy connection")

	err := client_session.connection.Close()
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage("error with closing connection to acraproxy", err))
	}
	log.Println("Debug: close db connection")
	err = client_session.connection_to_db.Close()
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage("error with closing connection to db", err))
	}
	log.Println("Debug: all connections closed")
}

/* proxy connections from client to db and decrypt responses from db to client
if any error occurred than end processing
*/
func (client_session *ClientSession) HandleSecureSession(decryptor_impl base.Decryptor) {
	inner_error_channel := make(chan error, 2)

	err := client_session.ConnectToDb()
	if err != nil {
		log.Printf("Error: %v\n", ErrorMessage("can't connect to db", err))
		log.Println("Debug: close connection with acraproxy")
		err = client_session.connection.Close()
		if err != nil {
			log.Printf("Warning: %v\n", ErrorMessage("error with closing connection to acraproxy", err))
		}
		return
	}

	go client_session.proxyConnections(inner_error_channel)
	// postgresql usually use 8kb for buffers
	reader := bufio.NewReaderSize(client_session.connection_to_db, 8192)
	writer := bufio.NewWriter(client_session)

	go postgresql.PgDecryptStream(decryptor_impl, reader, writer, inner_error_channel)
	err = <-inner_error_channel
	if err == io.EOF {
		log.Println("Debug: EOF connection closed")
	} else if netErr, ok := err.(net.Error); ok {
		log.Printf("Error: %v\n", ErrorMessage("network error", netErr))
	} else if opErr, ok := err.(*net.OpError); ok {
		log.Printf("Error: %v\n", ErrorMessage("network error", opErr))
	} else {
		fmt.Printf("Error: %v\n", ErrorMessage("unexpected error", err))
	}
	client_session.close()
	// wait second error from closed second connection
	err = <-inner_error_channel
}
