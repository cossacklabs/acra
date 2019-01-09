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

package network

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"

	"errors"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/session"
	log "github.com/sirupsen/logrus"
	"time"
)

const (
	// sessionInitTimeout should be enough 5 seconds for secure session initialization and handshake
	// chosen manually
	sessionInitTimeout = time.Second * 5
)

// SessionCallback used for wrapping connection into SecureSession using SecureSession transport keys
type SessionCallback struct {
	keystorage keystore.SecureSessionKeyStore
	expectedID []byte
}

// GetPublicKeyForId from Themis, returns correct public for particular secure session id
func (callback *SessionCallback) GetPublicKeyForId(ss *session.SecureSession, id []byte) *keys.PublicKey {
	if !bytes.Equal(id, callback.expectedID) {
		log.WithField("client_id", id).Warningln("Come secure session connection with unexpected id")
		return nil
	}
	log.Infof("Load public key for id <%v>", string(id))
	key, err := callback.keystorage.GetPeerPublicKey(id)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadKeys).
			Errorf("Can't load public key for id <%v>", string(id))
		return nil
	}
	return key
}

// StateChanged callback for session state change
func (callback *SessionCallback) StateChanged(ss *session.SecureSession, state int) {}

// NewSessionCallback creates new SessionCallback with SecureSessionKeyStore
func NewSessionCallback(expectedID []byte, keystorage keystore.SecureSessionKeyStore) (*SessionCallback, error) {
	return &SessionCallback{keystorage: keystorage, expectedID: expectedID}, nil
}

type secureSessionConnection struct {
	keystore keystore.SecureSessionKeyStore
	session  *session.SecureSession
	net.Conn
	currentData   []byte
	returnedIndex int
	closed        bool
	clientID      []byte
	mutex         *sync.Mutex
}

func newSecureSessionConnection(keystore keystore.SecureSessionKeyStore, conn net.Conn) (*secureSessionConnection, error) {
	return &secureSessionConnection{keystore: keystore, session: nil, Conn: conn, currentData: nil, returnedIndex: 0, closed: false, clientID: nil, mutex: &sync.Mutex{}}, nil
}

// Read data from connection, returns decrypted data
// returns decryption error or EOF error if connection closed
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

// Close secure session connection, close all underlying connections
func (wrapper *secureSessionConnection) Close() error {
	wrapper.mutex.Lock()
	defer wrapper.mutex.Unlock()
	wrapper.closed = true
	err := wrapper.Conn.Close()
	sessionErr := wrapper.session.Close()
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

// SecureSessionEstablishingTimeout timeout for secure session handshake that should be enough
const SecureSessionEstablishingTimeout = time.Second * 10

// MaxClientIDDataLength max data length of first packet that send from client. 1 kb was chosen manually and that should
// be enough
const MaxClientIDDataLength = 1024 // 1kb

// ErrClientIDPacketToBig show that packet with ClientID too big
var ErrClientIDPacketToBig = errors.New("packet with ClientID too big")

// SecureSessionConnectionWrapper adds SecureSession encryption above connection
type SecureSessionConnectionWrapper struct {
	keystore         keystore.SecureSessionKeyStore
	handshakeTimeout time.Duration
	id               []byte
}

// NewSecureSessionConnectionWrapper returns new SecureSessionConnectionWrapper with default handlshake timeout
func NewSecureSessionConnectionWrapper(id []byte, keystore keystore.SecureSessionKeyStore) (*SecureSessionConnectionWrapper, error) {
	return &SecureSessionConnectionWrapper{keystore: keystore, id: id, handshakeTimeout: SecureSessionEstablishingTimeout}, nil
}

// SetHandshakeTimeout set handshakeTimeout that will be used for secure session handshake. 0 - without handshakeTimeout
func (wrapper *SecureSessionConnectionWrapper) SetHandshakeTimeout(time time.Duration) {
	wrapper.handshakeTimeout = time
}

func (wrapper *SecureSessionConnectionWrapper) hasHandshakeTimeout() bool {
	return wrapper.handshakeTimeout != 0
}

func (wrapper *SecureSessionConnectionWrapper) wrap(outgoingID []byte, conn net.Conn, isServer bool) (net.Conn, []byte, error) {
	conn.SetDeadline(time.Now().Add(sessionInitTimeout))
	defer conn.SetDeadline(time.Time{})
	secureConnection, err := newSecureSessionConnection(wrapper.keystore, conn)
	if err != nil {
		return conn, nil, err
	}
	var clientID []byte
	if isServer {
		lengthBuf, length, err := utils.ReadDataLength(conn)
		if err != nil {
			return conn, lengthBuf, err
		}
		if length > MaxClientIDDataLength {
			return conn, lengthBuf, ErrClientIDPacketToBig
		}
		clientID = make([]byte, length)
		_, err = io.ReadFull(conn, clientID)
		if err != nil {
			return conn, nil, err
		}
		log.WithField("client_id", string(clientID)).Debugln("New secure session connection to server")
		privateKey, err := wrapper.keystore.GetPrivateKey(clientID)
		if err != nil {
			return conn, nil, err
		}
		callback, err := NewSessionCallback(clientID, wrapper.keystore)
		if err != nil {
			return conn, nil, err
		}
		secureConnection.session, err = session.New(wrapper.id, privateKey, callback)
		if err != nil {
			return conn, nil, err
		}
	} else {
		clientID = outgoingID
		privateKey, err := wrapper.keystore.GetPrivateKey(wrapper.id)
		if err != nil {
			return conn, nil, err
		}
		callback, err := NewSessionCallback(outgoingID, wrapper.keystore)
		if err != nil {
			return conn, nil, err
		}
		secureConnection.session, err = session.New(wrapper.id, privateKey, callback)
		if err != nil {
			return conn, nil, err
		}
		err = utils.SendData(wrapper.id, conn)
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
			return secureConnection, clientID, nil
		}

		err = utils.SendData(buf, conn)
		if err != nil {
			return conn, nil, err
		}

		if secureConnection.session.GetState() == session.STATE_ESTABLISHED {
			return secureConnection, clientID, nil
		}
	}
}

// WrapClient wraps client connection with secure session
// cancels connection if timeout expired
func (wrapper *SecureSessionConnectionWrapper) WrapClient(ctx context.Context, id []byte, conn net.Conn) (net.Conn, error) {
	logger := logging.NewLoggerWithTrace(ctx)
	logger.Debugln("Wrap client connection with secure session")
	if wrapper.hasHandshakeTimeout() {
		if err := conn.SetDeadline(time.Now().Add(wrapper.handshakeTimeout)); err != nil {
			logger.WithError(err).Errorln("Can't set deadline for secure session handshake")
			return nil, err
		}
	}
	newConn, _, err := wrapper.wrap(id, conn, false)
	if wrapper.hasHandshakeTimeout() {
		// reset deadline
		if err := conn.SetDeadline(time.Time{}); err != nil {
			logger.WithError(err).Errorln("Can't reset deadline after secure session handshake")
			return nil, err
		}
	}
	logger.Debugln("Wrap client connection with secure session finished")
	return newSafeCloseConnection(newConn), NewConnectionWrapError(err)
}

// WrapServer wraps server connection with secure session
// cancels connection if timeout expired
func (wrapper *SecureSessionConnectionWrapper) WrapServer(ctx context.Context, conn net.Conn) (net.Conn, []byte, error) {
	logger := logging.NewLoggerWithTrace(ctx)
	logger.Debugln("Wrap server connection with secure session")
	if wrapper.hasHandshakeTimeout() {
		if err := conn.SetDeadline(time.Now().Add(wrapper.handshakeTimeout)); err != nil {
			log.WithError(err).Errorln("Can't set deadline for secure session handshake")
			return nil, nil, err
		}
	}
	newConn, clientID, err := wrapper.wrap(nil, conn, true)
	if wrapper.hasHandshakeTimeout() {
		// reset deadline
		if err := conn.SetDeadline(time.Time{}); err != nil {
			logger.WithError(err).Errorln("Can't reset deadline after secure session handshake")
			return nil, nil, err
		}
	}
	logger.Debugln("Wrap server connection with secure session finished")
	return newSafeCloseConnection(newConn), clientID, NewConnectionWrapError(err)
}
