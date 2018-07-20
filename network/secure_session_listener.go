package network

import (
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
func NewSecureSessionListener(connectionString string, keystorage keystore.SecureSessionKeyStore) (*SecureSessionListener, error) {
	connectionWrapper, err := NewSecureSessionConnectionWrapper(keystorage)
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
	wrappedConnection, _, err := listener.wrapper.WrapServer(conn)
	if err != nil {
		log.WithError(err).Errorln("Can't wrap connection with secure session")
		// mark that it's not fatal error and may be temporary (need for grpc that stop listening on non-temporary error
		// from listener.Accept
		return nil, err
	}
	return wrappedConnection, nil
}
