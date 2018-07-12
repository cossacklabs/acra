package network

import (
	"net"

	"github.com/cossacklabs/acra/keystore"
)

type SecureSessionListener struct {
	net.Listener
	keystorage keystore.SecureSessionKeyStore
	wrapper    *SecureSessionConnectionWrapper
}

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

func (listener *SecureSessionListener) Accept() (net.Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wrappedConnection, _, err := listener.wrapper.WrapServer(conn)
	if err != nil {
		return nil, err
	}
	return wrappedConnection, nil
}
