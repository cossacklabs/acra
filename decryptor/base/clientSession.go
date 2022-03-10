package base

import (
	"context"
	"net"
)

// ClientSession is a connection between the client and the database, mediated by AcraServer.
type ClientSession interface {
	Context() context.Context
	ClientConnection() net.Conn
	DatabaseConnection() net.Conn

	PreparedStatementRegistry() PreparedStatementRegistry
	SetPreparedStatementRegistry(registry PreparedStatementRegistry)

	ProtocolState() interface{}
	SetProtocolState(state interface{})
	GetData(string) (interface{}, bool)
	SetData(string, interface{})
	DeleteData(string)
	HasData(string) bool
}

type sessionContextKey struct{}

// SetClientSessionToContext return context with saved ClientSession
func SetClientSessionToContext(ctx context.Context, session ClientSession) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, session)
}

// ClientSessionFromContext return saved ClientSession from context or nil
func ClientSessionFromContext(ctx context.Context) ClientSession {
	value := ctx.Value(sessionContextKey{})
	session, ok := value.(ClientSession)
	if ok {
		return session
	}
	return nil
}
