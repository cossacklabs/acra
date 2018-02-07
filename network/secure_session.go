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
package network

import (
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/themis/gothemis/session"
	"github.com/cossacklabs/themis/gothemis/keys"
	"log"
	"net"
	"github.com/cossacklabs/acra/utils"
	"errors"
)

type SecureSessionConnection struct{
	keystore keystore.KeyStore
	session *session.SecureSession
	net.Conn
}

func NewSecureSessionConnection(connection net.Conn, keystore keystore.KeyStore, session *session.SecureSession)(*SecureSessionConnection, error){
	return &SecureSessionConnection{keystore: keystore, Conn: connection, session: session}, nil
}

func (conn *SecureSessionConnection) Read(b []byte) (n int, err error){
	data, err := utils.ReadData(conn.Conn)
	if err != nil{
		return len(data), err
	}
	decryptedData, _, err := conn.session.Unwrap(data)
	if err != nil{
		return len(data), err
	}
	if len(b) != len(decryptedData){
		log.Println("error: output data length != input data length")
		return len(data), errors.New("incorrect read data length")
	}
	n = copy(b, decryptedData)
	return
}

// Write writes data to the connection.
// Write can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (conn *SecureSessionConnection) Write(b []byte) (n int, err error){
	encryptedData, err := conn.session.Wrap(b)
	if err != nil{
		return 0, err
	}
	err = utils.SendData(encryptedData, conn.Conn)
	return len(b), nil
}