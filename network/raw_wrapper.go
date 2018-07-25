// Package network contains network utils for establishing secure session, for listening connections.
//
package network

import "net"

type RawConnectionWrapper struct {
	net.Conn
	ClientID []byte
}

func (wrapper *RawConnectionWrapper) WrapClient(id []byte, conn net.Conn) (net.Conn, error) {
	wrapper.Conn = conn
	return conn, nil
}
func (wrapper *RawConnectionWrapper) WrapServer(conn net.Conn) (net.Conn, []byte, error) {
	wrapper.Conn = conn
	return conn, wrapper.ClientID, nil
}
