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
	"context"
	"github.com/cossacklabs/acra/logging"
	"net"

	"github.com/cossacklabs/acra/keystore"
	log "github.com/sirupsen/logrus"
)

// SecureSessionListener implement net.Listener and wrap all connections on listener.Accept before returning with
// SecureSession
type SecureSessionListener struct {
	net.Listener
	keystorage keystore.SecureSessionKeyStore
	wrapper    *SecureSessionConnectionWrapper
}

// NewSecureSessionListener create SecureSessionConnectionWrapper that will use keystorage to wrap new connections, create
// listener by connectionString and return SecureSessionListener
func NewSecureSessionListener(id []byte, connectionString string, keystorage keystore.SecureSessionKeyStore) (*SecureSessionListener, error) {
	connectionWrapper, err := NewSecureSessionConnectionWrapper(id, keystorage)
	if err != nil {
		return nil, err
	}
	listener, err := Listen(connectionString)
	if err != nil {
		return nil, err
	}
	return &SecureSessionListener{Listener: listener, keystorage: keystorage, wrapper: connectionWrapper}, nil
}

// Accept new connection and wrap with secure session before return
// return ConnectionWrapError if error wa
func (listener *SecureSessionListener) Accept() (net.Conn, error) {
	log.Info("Start accept connections via secure session listener")
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wrappedConnection, _, err := listener.wrapper.WrapServer(context.TODO(), conn)
	if err != nil {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantWrapConnection).WithError(err).Errorln("Can't wrap connection with secure session")
		// mark that it's not fatal error and may be temporary (need for grpc that stop listening on non-temporary error
		// from listener.Accept
		return nil, err
	}
	// connector always send trace, but now we can't pass it to grpc method
	_, err = ReadTrace(wrappedConnection)
	if err != nil {
		return nil, err
	}
	return wrappedConnection, nil
}
