package network

import (
	"net"
	"crypto/tls"
)

type TLSConnectionWrapper struct{
	net.Conn
	config *tls.Config
}

func NewTLSConnectionWrapper(config *tls.Config)(*TLSConnectionWrapper, error){
	return &TLSConnectionWrapper{config: config}, nil
}

func (wrapper *TLSConnectionWrapper) WrapClient(id []byte, conn net.Conn)(net.Conn, error){
	tlsConn := tls.Client(conn, wrapper.config)
	err := tlsConn.Handshake()
	if err != nil{
		return conn, err
	}
	wrapper.Conn = tlsConn
	return tlsConn, nil
}
func (wrapper *TLSConnectionWrapper) WrapServer(id []byte, conn net.Conn)(net.Conn, error){
	tlsConn := tls.Server(conn, wrapper.config)
	err := tlsConn.Handshake()
	if err != nil{
		return conn, err
	}
	wrapper.Conn = tlsConn
	return tlsConn, nil
}