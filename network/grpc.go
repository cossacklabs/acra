package network

import (
	"google.golang.org/grpc/credentials"
	"net"
)

// authInfoConnectionAccess interface used to access to connection
type authInfoConnectionAccess interface {
	Connection() net.Conn
}

// GetClientIDFromAuthInfo extracts clientID data from credentials.AuthInfo if it's saved by SecureSession or TLS wrappers
// In second case will be used tlsExtractor to extract clientID from TLS metadata
func GetClientIDFromAuthInfo(authInfo credentials.AuthInfo, tlsExtractor TLSClientIDExtractor) ([]byte, error) {
	connAccess, ok := authInfo.(authInfoConnectionAccess)
	if !ok {
		return nil, ErrCantExtractClientID
	}
	clientID, ok := GetClientIDFromConnection(connAccess.Connection(), tlsExtractor)
	if !ok {
		return nil, ErrCantExtractClientID
	}
	return clientID, nil
}

// OnServerHandshakeCallback interface used for callbacks on every ServerHandshake call in grpc connection handler
type OnServerHandshakeCallback interface {
	OnServerHandshake(net.Conn) (net.Conn, error)
}

// GRPCConnectionWrapper interface implements credentials.TransportCredentials and allows to register callbacks for new connections
// after ServerHandshake call
type GRPCConnectionWrapper interface {
	credentials.TransportCredentials
	AddOnServerHandshakeCallback(callback OnServerHandshakeCallback)
}
