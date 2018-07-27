// Package network contains network utils for establishing secure session, for listening connections.
//
package network

import (
	"net"
)

// ConnectionTimeoutWrapper interface
type ConnectionTimeoutWrapper interface {
	net.Conn
}

// ConnectionWrapper interface
type ConnectionWrapper interface {
	WrapClient(id []byte, conn net.Conn) (net.Conn, error)
	WrapServer(conn net.Conn) (net.Conn, []byte, error) // conn, ClientID, error
}
