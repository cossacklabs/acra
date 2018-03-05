package network

import (
	"crypto/tls"
	"net"
)

type TLSConnectionWrapper struct {
	config   *tls.Config
	clientId []byte
}

func NewTLSConnectionWrapper(clientId []byte, config *tls.Config) (*TLSConnectionWrapper, error) {
	return &TLSConnectionWrapper{config: config, clientId: clientId}, nil
}

func (wrapper *TLSConnectionWrapper) WrapClient(id []byte, conn net.Conn) (net.Conn, error) {
	tlsConn := tls.Client(conn, wrapper.config)
	err := tlsConn.Handshake()
	if err != nil {
		return conn, err
	}
	return tlsConn, nil
}
func (wrapper *TLSConnectionWrapper) WrapServer(conn net.Conn) (net.Conn, []byte, error) {
	tlsConn := tls.Server(conn, wrapper.config)
	err := tlsConn.Handshake()
	if err != nil {
		return conn, nil, err
	}
	return tlsConn, wrapper.clientId, nil
}
