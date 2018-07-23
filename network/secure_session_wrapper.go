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
	"io"
	"net"
	"sync"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/session"
	log "github.com/sirupsen/logrus"
	"time"
)

type SessionCallback struct {
	keystorage keystore.SecureSessionKeyStore
}

func (callback *SessionCallback) GetPublicKeyForId(ss *session.SecureSession, id []byte) *keys.PublicKey {
	log.Infof("Load public key for id %v", string(id))
	key, err := callback.keystorage.GetPeerPublicKey(id)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadKeys).
			Errorf("Can't load public key for id %v", string(id))
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
	currentData   []byte
	returnedIndex int
	closed        bool
	clientId      []byte
	mutex         *sync.Mutex
}

func newSecureSessionConnection(keystore keystore.SecureSessionKeyStore, conn net.Conn) (*secureSessionConnection, error) {
	return &secureSessionConnection{keystore: keystore, session: nil, Conn: conn, currentData: nil, returnedIndex: 0, closed: false, clientId: nil, mutex: &sync.Mutex{}}, nil
}

func (wrapper *secureSessionConnection) Read(b []byte) (n int, err error) {
	if wrapper.currentData != nil {
		n = copy(b, wrapper.currentData[wrapper.returnedIndex:])
		wrapper.returnedIndex += n
		if wrapper.returnedIndex >= cap(wrapper.currentData) {
			wrapper.currentData = nil
		}
		return n, err
	}
	data, err := utils.ReadData(wrapper.Conn)
	if err != nil {
		return len(data), err
	}
	wrapper.mutex.Lock()
	defer wrapper.mutex.Unlock()
	if wrapper.closed {
		return 0, io.EOF
	}
	decryptedData, _, err := wrapper.session.Unwrap(data)
	if err != nil {
		return len(data), err
	}
	n = copy(b, decryptedData)
	if n != len(decryptedData) {
		wrapper.currentData = decryptedData
		wrapper.returnedIndex = n
	}

	return n, nil
}

// Write encrypt data with secure session and send it to wrapped connection
func (wrapper *secureSessionConnection) Write(b []byte) (n int, err error) {
	wrapper.mutex.Lock()
	if wrapper.closed {
		wrapper.mutex.Unlock()
		return 0, io.EOF
	}
	encryptedData, err := wrapper.session.Wrap(b)
	if err != nil {
		wrapper.mutex.Unlock()
		return 0, err
	}
	wrapper.mutex.Unlock()
	err = utils.SendData(encryptedData, wrapper.Conn)
	return len(b), nil
}

func (wrapper *secureSessionConnection) Close() error {
	wrapper.mutex.Lock()
	defer wrapper.mutex.Unlock()
	wrapper.closed = true
	err := wrapper.Conn.Close()
	sessionErr := wrapper.session.Close()
	log.Debugln("secure session connection closed")
	if sessionErr != nil {
		return sessionErr
	}
	return err
}

// ConnectionWrapError wrap error and always return true on net.Error.Temporary and false on net.Error.Timeout
type ConnectionWrapError struct{ error }

// NewConnectionWrapError wrap err with ConnectionWrapError
func NewConnectionWrapError(err error) error {
	if err == nil {
		return nil
	}
	return &ConnectionWrapError{err}
}

// Error value of wrapped error
func (err *ConnectionWrapError) Error() string {
	return err.error.Error()
}

// Timeout return Timeout() of wrapped error or false
func (err *ConnectionWrapError) Timeout() bool {
	netErr, ok := err.error.(net.Error)
	if ok {
		return netErr.Timeout()
	}
	return false
}

// Temporary always true
func (err *ConnectionWrapError) Temporary() bool {
	return true
}

// SECURE_SESSION_ESTABLISHING_TIMEOUT timeout for secure session handshake that should be enough
const SECURE_SESSION_ESTABLISHING_TIMEOUT = time.Second * 10

type SecureSessionConnectionWrapper struct {
	keystore         keystore.SecureSessionKeyStore
	clientId         []byte
	handshakeTimeout time.Duration
}

func NewSecureSessionConnectionWrapper(keystore keystore.SecureSessionKeyStore) (*SecureSessionConnectionWrapper, error) {
	return &SecureSessionConnectionWrapper{keystore: keystore, clientId: nil, handshakeTimeout: SECURE_SESSION_ESTABLISHING_TIMEOUT}, nil
}

// SetHandshakeTimeout set handshakeTimeout that will be used for secure session handshake. 0 - without handshakeTimeout
func (wrapper *SecureSessionConnectionWrapper) SetHandshakeTimeout(time time.Duration) {
	wrapper.handshakeTimeout = time
}

func (wrapper *SecureSessionConnectionWrapper) hasHandshakeTimeout() bool {
	return wrapper.handshakeTimeout != 0
}

func (wrapper *SecureSessionConnectionWrapper) wrap(id []byte, conn net.Conn, isServer bool) (net.Conn, []byte, error) {
	secureConnection, err := newSecureSessionConnection(wrapper.keystore, conn)
	if err != nil {
		return conn, nil, err
	}
	callback, err := NewSessionCallback(wrapper.keystore)
	if err != nil {
		return conn, nil, err
	}
	var clientId []byte
	if isServer {
		clientId, err = utils.ReadData(conn)
		if err != nil {
			return conn, nil, err
		}
		log.WithField("client_id", string(clientId)).Debugln("new secure session connection to server")
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
		if err != nil {
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
	log.Debugln("wrap client connection with secure session")
	if wrapper.hasHandshakeTimeout() {
		if err := conn.SetDeadline(time.Now().Add(wrapper.handshakeTimeout)); err != nil {
			log.WithError(err).Errorln("Can't set deadline for secure session handshake")
			return nil, err
		}
	}
	newConn, _, err := wrapper.wrap(id, conn, false)
	if wrapper.hasHandshakeTimeout() {
		// reset deadline
		if err := conn.SetDeadline(time.Time{}); err != nil {
			log.WithError(err).Errorln("Can't reset deadline after secure session handshake")
			return nil, err
		}
	}
	log.Debugln("wrap client connection with secure session finished")
	return newConn, NewConnectionWrapError(err)
}
func (wrapper *SecureSessionConnectionWrapper) WrapServer(conn net.Conn) (net.Conn, []byte, error) {
	log.Debugln("wrap server connection with secure session")
	if wrapper.hasHandshakeTimeout() {
		if err := conn.SetDeadline(time.Now().Add(wrapper.handshakeTimeout)); err != nil {
			log.WithError(err).Errorln("Can't set deadline for secure session handshake")
			return nil, nil, err
		}
	}
	newConn, clientId, err := wrapper.wrap(nil, conn, true)
	if wrapper.hasHandshakeTimeout() {
		// reset deadline
		if err := conn.SetDeadline(time.Time{}); err != nil {
			log.WithError(err).Errorln("Can't reset deadline after secure session handshake")
			return nil, nil, err
		}
	}
	log.Debugln("wrap server connection with secure session finished")
	return newConn, clientId, NewConnectionWrapError(err)
}
