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
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/cossacklabs/acra/config"
	"github.com/cossacklabs/acra/keystore"
	. "github.com/cossacklabs/acra/utils"
)

type ClientCommandsSession struct {
	ClientSession
}

func NewClientCommandsSession(client_id []byte, config *config.Config, connection net.Conn) (*ClientCommandsSession, error) {
	client_session, err := NewClientSession(client_id, config, connection)
	if err != nil {
		return nil, err
	}
	return &ClientCommandsSession{*client_session}, nil

}

func (client_session *ClientCommandsSession) ConnectToDb() error {
	return fmt.Errorf("Error: command session must not connect to any DB")
}

/* read packets from client app wrapped in ss, unwrap them and send to db as is */
func (client_session *ClientCommandsSession) proxyConnections() {
	return
}

func (client_session *ClientCommandsSession) close() {
	log.Println("Debug: close acraproxy connection")
	err := client_session.connection.Close()
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage("error with closing connection to acraproxy", err))
	}
	log.Println("Debug: all connections closed")
}

func (client_session *ClientCommandsSession) HandleSession() {
	data, err := ReadData(client_session.connection)
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage("can't initialize secure session with acraproxy", err))
		return
	}

	decrypted_data, _, err := client_session.session.Unwrap(data)
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage("can't initialize secure session with acraproxy", err))
		return
	}
	reader := bufio.NewReader(strings.NewReader(string(decrypted_data[:])))
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage("error reading command request from proxy", err))
		client_session.close()
		return
	}
	response := "HTTP/1.1 404 Not Found\r\n\r\nincorrect request\r\n\r\n"
	switch req.URL.Path {
	case "/getNewZone":
		new_zone, err := keystore.AddNewZone(client_session.config.GetKeysDir(), true)
		if err == nil {
			response = "HTTP/1.1 200 OK Found\r\n\r\n" + new_zone + "\r\n\r\n"
		}
	}
	_, err = client_session.Write([]byte(response))
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage("can't send data with secure session to acraproxy", err))
		return
	}
	client_session.close()
}
