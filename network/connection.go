package network

import (
	"crypto/tls"
	"net"
)

// WrappedConnection interface implemented by connection wrappers to access to wrapped connection
type WrappedConnection interface {
	Unwrap() net.Conn
}

type clientIDConnection struct {
	net.Conn
	clientID []byte
}

func newClientIDConnection(conn net.Conn, clientID []byte) *clientIDConnection {
	return &clientIDConnection{Conn: conn, clientID: clientID}
}

// Unwrap returns wrapped connection
func (conn *clientIDConnection) Unwrap() net.Conn {
	return conn.Conn
}

// GetClientIDFromConnection extract clientID from conn if it's safeCloseConnection otherwise nil, false
func GetClientIDFromConnection(conn net.Conn, tlsExtractor TLSClientIDExtractor) ([]byte, bool) {
	// unwrap until find connectionWithMetadata or return false if it's pure net.Conn
	for {
		unwrapped, ok := conn.(WrappedConnection)
		if !ok {
			// if it's http2 server that require top type of connection tls.Conn and we can't wrap it with our wrappers
			// then try to extract clientID from pure tls.Conn
			if tlsExtractor != nil {
				if tlsConn, ok := conn.(*tls.Conn); ok {
					clientID, err := GetClientIDFromTLSConn(tlsConn, tlsExtractor)
					if err != nil {
						return nil, false
					}
					return clientID, true
				}
			}
			return nil, false
		}
		if connWithMetadata, ok := unwrapped.(*clientIDConnection); ok {
			return connWithMetadata.clientID, true
		}
		conn = unwrapped.Unwrap()
	}
}
