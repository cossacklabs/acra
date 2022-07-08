/*
Copyright 2016, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package network

import (
	"context"
	"errors"
	"net"

	"go.opencensus.io/trace"
)

// ConnectionTimeoutWrapper interface
type ConnectionTimeoutWrapper interface {
	net.Conn
}

// ConnectionMetadata connection metadata
type ConnectionMetadata interface {
	SpanContext() (trace.SpanContext, bool)
	ClientID() ([]byte, bool)
}

// ConnectionWrapper interface
type ConnectionWrapper interface {
	WrapClient(ctx context.Context, conn net.Conn) (net.Conn, error)
	WrapServer(ctx context.Context, conn net.Conn) (net.Conn, []byte, error) // conn, ClientID, error
}

var (
	// ErrCantExtractClientID used when can't extract ClientID from gRPC connection handshake
	ErrCantExtractClientID = errors.New("can't extract ClientID from gRPC connection")
	// ErrIncorrectGRPCConnectionAuthInfo used if gRPC connection AuthState has unsupported type
	ErrIncorrectGRPCConnectionAuthInfo = errors.New("incorrect auth info from gRPC connection")
)

// GRPCConnectionClientIDExtractor extract clientID from connection AuthInfo encapsulated in request context
type GRPCConnectionClientIDExtractor interface {
	ExtractClientID(context.Context) ([]byte, error)
}

// ConnectionCallback used to call callbacks on new accepted connections
type ConnectionCallback interface {
	OnConnection(net.Conn) (net.Conn, error)
}

// ConnectionContextCallback used to call callbacks for http.Server.ConnContext calls
type ConnectionContextCallback interface {
	OnConnectionContext(ctx context.Context, c net.Conn) (context.Context, error)
}

type connContextKey struct{}

// ConnectionToContextCallback callback implements OnConnectionContextCallback interface and store connection in context
type ConnectionToContextCallback struct{}

// OnConnectionContext return context with saved connection for future retrieving from context in http.Server handlers
func (ConnectionToContextCallback) OnConnectionContext(ctx context.Context, c net.Conn) (context.Context, error) {
	return SetConnectionToHTTPContext(ctx, c), nil
}

// SetConnectionToHTTPContext set connection to context and may be used as ConnContext callback for http.Server
func SetConnectionToHTTPContext(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, connContextKey{}, conn)
}

// GetConnectionFromHTTPContext return net.Conn or nil if not found
func GetConnectionFromHTTPContext(ctx context.Context) net.Conn {
	conn, ok := ctx.Value(connContextKey{}).(net.Conn)
	if ok {
		return conn
	}
	return nil
}

type connClientIDKey struct{}

// ClientIDToContextCallback is a callback that sets the ClientID into the connection
// context. Is used in the TLS connections to specify static clientID, instead of
// extracting it from the certificate.
type ClientIDToContextCallback struct {
	ClientID []byte
}

// OnConnectionContext returns connection context with the clientID saved.
func (c ClientIDToContextCallback) OnConnectionContext(ctx context.Context, _ net.Conn) (context.Context, error) {
	return SetClientIDToHTTPContext(ctx, c.ClientID), nil
}

// SetClientIDToHTTPContext returns new context with the clientID.
func SetClientIDToHTTPContext(ctx context.Context, clientID []byte) context.Context {
	return context.WithValue(ctx, connClientIDKey{}, clientID)
}

// GetClientIDFromHTTPContext returns clientID if it was set into the context.
func GetClientIDFromHTTPContext(ctx context.Context) ([]byte, bool) {
	clientID, ok := ctx.Value(connClientIDKey{}).([]byte)
	return clientID, ok
}
