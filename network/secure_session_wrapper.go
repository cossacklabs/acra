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
	"io"
	"net"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"log"
)

type SessionCallback struct {
	keystorage keystore.SecureSessionKeyStore
}

func (callback *SessionCallback) GetPublicKeyForId(ss *session.SecureSession, id []byte) *keys.PublicKey {
	log.Printf("Info: load public key for id <%v>\n", string(id))
	key, err := callback.keystorage.GetPeerPublicKey(id)
	if err != nil {
		log.Printf("Error: can't load public key for id <%v>\n", string(id))
		return nil
	}
	return key
}

func (callback *SessionCallback) StateChanged(ss *session.SecureSession, state int) {}

func NewSessionCallback(keystorage keystore.SecureSessionKeyStore) (*SessionCallback, error) {
	return &SessionCallback{keystorage: keystorage}, nil
}

type secureSessionConnection struct {
	keystore keystore.SecureSessionKeyStore
	session  *session.SecureSession
	net.Conn
	currentData []byte
	returnedIndex int
	closed bool
	clientId []byte
}

func newSecureSessionConnection(keystore keystore.SecureSessionKeyStore, conn net.Conn)(*secureSessionConnection, error){
	return &secureSessionConnection{keystore: keystore, session: nil, Conn: conn, currentData: nil, returnedIndex:0, closed: false, clientId: nil}, nil
}

func (wrapper *secureSessionConnection) isClosed()bool {
	return wrapper.closed
}

func (wrapper *secureSessionConnection) Read(b []byte) (n int, err error) {
	if wrapper.closed {
		return 0, io.EOF
	}
	if wrapper.currentData != nil {
		log.Println("SS wrapper: copy cached data")
		n = copy(b, wrapper.currentData[wrapper.returnedIndex:])
		log.Printf("SS wrapper: copied %v bytes\n", n)
		wrapper.returnedIndex += n
		if wrapper.returnedIndex >= cap(wrapper.currentData){
			log.Println("SS wrapper: cache empty")
			wrapper.currentData = nil
		}
		return n, err
	}
	log.Println("SS wrapper: read data from connection")
	data, err := utils.ReadData(wrapper.Conn)
	if err != nil {
		return len(data), err
	}
	log.Printf("SS wrapper: read %v bytes\n", len(data))
	decryptedData, _, err := wrapper.session.Unwrap(data)
	if err != nil {
		return len(data), err
	}
	log.Printf("SS wrapper: decrypted into %v bytes\n", len(decryptedData))
	n = copy(b, decryptedData)
	log.Printf("SS wrapper: copied decrypted data %v bytes\n", n)
	if n != len(decryptedData){
		log.Println("SS wrapper: saved cached least data", n)
		wrapper.currentData = decryptedData
		wrapper.returnedIndex = n
	}
	return n, nil
}

// Write writes data to the connection.
// Write can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (wrapper *secureSessionConnection) Write(b []byte) (n int, err error) {
	if wrapper.closed {
		return 0, io.EOF
	}
	encryptedData, err := wrapper.session.Wrap(b)
	if err != nil {
		return 0, err
	}
	err = utils.SendData(encryptedData, wrapper.Conn)
	return len(b), nil
}

func (wrapper *secureSessionConnection) Close() error {
	wrapper.closed = true
	log.Println("close wrapped connection in wrapper")
	err := wrapper.Conn.Close()

	sessionErr := wrapper.session.Close()
	if sessionErr != nil{
		return sessionErr
	}
	log.Println("close secure session")

	return err
}

type SecureSessionConnectionWrapper struct {
	keystore keystore.SecureSessionKeyStore
	clientId []byte
}

func NewSecureSessionConnectionWrapper(keystore keystore.SecureSessionKeyStore, ) (*SecureSessionConnectionWrapper, error) {
	return &SecureSessionConnectionWrapper{keystore: keystore, clientId: nil}, nil
}

func (wrapper *SecureSessionConnectionWrapper) wrap(id []byte, conn net.Conn, isServer bool) (net.Conn, []byte, error) {
	secureConnection, err := newSecureSessionConnection(wrapper.keystore, conn)
	if err != nil{
		return conn, nil, err
	}
	callback, err := NewSessionCallback(wrapper.keystore)
	if err != nil {
		return conn, nil, err
	}
	var clientId []byte
	if isServer{
		clientId, err = utils.ReadData(conn)
		if err != nil{
			return conn, nil, err
		}
		privateKey, err := wrapper.keystore.GetPrivateKey(clientId)
		if err != nil {
			return conn, nil, err
		}
		secureConnection.session, err = session.New(clientId, privateKey, callback)
		if err != nil {
			return conn, nil, err
		}
	} else {
		clientId = id
		privateKey, err := wrapper.keystore.GetPrivateKey(id)
		if err != nil {
			return conn, nil, err
		}
		secureConnection.session, err = session.New(id, privateKey, callback)
		if err != nil {
			return conn, nil, err
		}
		err = utils.SendData(id, conn)
		if err != nil{
			return conn, nil, err
		}
		connectRequest, err := secureConnection.session.ConnectRequest()
		if err != nil {
			return conn, nil, err
		}
		err = utils.SendData(connectRequest, conn)
		if err != nil {
			return conn, nil, err
		}
	}
	for {
		data, err := utils.ReadData(conn)
		if err != nil {
			return conn, nil, err
		}
		buf, sendPeer, err := secureConnection.session.Unwrap(data)
		if nil != err {
			return conn, nil, err
		}
		if !sendPeer {
			return secureConnection, clientId, nil
		}

		err = utils.SendData(buf, conn)
		if err != nil {
			return conn, nil, err
		}

		if secureConnection.session.GetState() == session.STATE_ESTABLISHED {
			return secureConnection, clientId, nil
		}
	}
}

func (wrapper *SecureSessionConnectionWrapper) WrapClient(id []byte, conn net.Conn) (net.Conn, error) {
	newConn, _, err := wrapper.wrap(id, conn, false)
	return newConn, err
}
func (wrapper *SecureSessionConnectionWrapper) WrapServer(conn net.Conn) (net.Conn, []byte, error) {
	return wrapper.wrap(nil, conn, true)
}
