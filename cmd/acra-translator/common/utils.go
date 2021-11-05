package common

import (
	"context"
	"net"
)

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
