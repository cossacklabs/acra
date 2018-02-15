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
	"net"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"log"
)

type SessionCallback struct {
	keystorage keystore.SecureSessionKeyStore
	conn       net.Conn
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

type SecureSessionConnectionWrapper struct {
	keystore keystore.SecureSessionKeyStore
	session  *session.SecureSession
	net.Conn
	currentData []byte
	returnedIndex int
}

func NewSecureSessionConnectionWrapper(keystore keystore.SecureSessionKeyStore, ) (*SecureSessionConnectionWrapper, error) {
	return &SecureSessionConnectionWrapper{keystore: keystore, session: nil}, nil
}
func (wrapper *SecureSessionConnectionWrapper) wrap(id []byte, conn net.Conn, isServer bool) (net.Conn, error) {
	wrapper.Conn = conn
	privateKey, err := wrapper.keystore.GetPrivateKey(id)
	if err != nil {
		return conn, err
	}
	callback, err := NewSessionCallback(wrapper.keystore)
	if err != nil {
		return conn, err
	}
	wrapper.session, err = session.New(id, privateKey, callback)
	if err != nil {
		return conn, err
	}
	if !isServer {
		connectRequest, err := wrapper.session.ConnectRequest()
		if err != nil {
			return conn, err
		}
		err = utils.SendData(connectRequest, conn)
		if err != nil {
			return conn, err
		}
	}
	for {
		data, err := utils.ReadData(conn)
		if err != nil {
			return conn, err
		}
		buf, sendPeer, err := wrapper.session.Unwrap(data)
		if nil != err {
			return conn, err
		}
		if !sendPeer {
			return wrapper, nil
		}

		err = utils.SendData(buf, conn)
		if err != nil {
			return conn, err
		}

		if wrapper.session.GetState() == session.STATE_ESTABLISHED {
			return wrapper, nil
		}
	}
}

func (wrapper *SecureSessionConnectionWrapper) WrapClient(id []byte, conn net.Conn) (net.Conn, error) {
	return wrapper.wrap(id, conn, false)
}
func (wrapper *SecureSessionConnectionWrapper) WrapServer(id []byte, conn net.Conn) (net.Conn, error) {
	return wrapper.wrap(id, conn, true)
}

func (wrapper *SecureSessionConnectionWrapper) Read(b []byte) (n int, err error) {
	if wrapper.currentData != nil {
		n = copy(b, wrapper.currentData[wrapper.returnedIndex:])
		wrapper.returnedIndex += n
		if wrapper.returnedIndex >= cap(wrapper.currentData){
			wrapper.currentData = nil
		}
		return n, err
	}
	data, err := utils.ReadData(wrapper.Conn)
	if err != nil {
		return len(data), err
	}
	decryptedData, _, err := wrapper.session.Unwrap(data)
	if err != nil {
		return len(data), err
	}
	n = copy(b, decryptedData)
	if n != len(decryptedData){
		wrapper.currentData = decryptedData
		wrapper.returnedIndex = n
	}
	return
}

// Write writes data to the connection.
// Write can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (wrapper *SecureSessionConnectionWrapper) Write(b []byte) (n int, err error) {
	encryptedData, err := wrapper.session.Wrap(b)
	if err != nil {
		return 0, err
	}
	err = utils.SendData(encryptedData, wrapper.Conn)
	return len(b), nil
}

func (wrapper *SecureSessionConnectionWrapper) Close() error {
	sessionErr := wrapper.session.Close()
	err := wrapper.Conn.Close()
	if sessionErr != nil{
		return sessionErr
	}
	return err
}
