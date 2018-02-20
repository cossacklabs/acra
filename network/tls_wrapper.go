package network

import (
	"net"
	"crypto/tls"
)

type TLSConnectionWrapper struct{
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
	return tlsConn, nil
}
func (wrapper *TLSConnectionWrapper) WrapServer(conn net.Conn)(net.Conn, []byte, error){
	tlsConn := tls.Server(conn, wrapper.config)
	err := tlsConn.Handshake()
	if err != nil{
		return conn, nil, err
	}
	return tlsConn, nil, nil
}