// Package network contains network utils for establishing secure session, for listening connections.
//
package network

import "net"

// RawConnectionWrapper doesn't add any encryption above connection
type RawConnectionWrapper struct {
	net.Conn
	ClientID []byte
}

// WrapClient returns RawConnectionWrapper above client connection
func (wrapper *RawConnectionWrapper) WrapClient(id []byte, conn net.Conn) (net.Conn, error) {
	wrapper.Conn = conn
	return conn, nil
}

// WrapServer returns RawConnectionWrapper above server connection
func (wrapper *RawConnectionWrapper) WrapServer(conn net.Conn) (net.Conn, []byte, error) {
	wrapper.Conn = conn
	return conn, wrapper.ClientID, nil
}
