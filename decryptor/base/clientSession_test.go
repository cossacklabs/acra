package base

import (
	"context"
	"net"
	"reflect"
	"testing"
)

type sessionStub struct{}

func (s sessionStub) Context() context.Context {
	panic("implement me")
}

func (s sessionStub) ClientConnection() net.Conn {
	panic("implement me")
}

func (s sessionStub) DatabaseConnection() net.Conn {
	panic("implement me")
}

func (s sessionStub) ProtocolState() interface{} {
	panic("implement me")
}

func (s sessionStub) SetProtocolState(state interface{}) {
	panic("implement me")
}

func (s sessionStub) GetData(s2 string) (interface{}, bool) {
	panic("implement me")
}

func (s sessionStub) SetData(s2 string, i interface{}) {
	panic("implement me")
}

func (s sessionStub) DeleteData(s2 string) {
	panic("implement me")
}

func (s sessionStub) HasData(s2 string) bool {
	panic("implement me")
}

func TestSetClientSessionToContext(t *testing.T) {
	session := sessionStub{}
	ctx := context.Background()
	if value := ClientSessionFromContext(ctx); value != nil {
		t.Fatal("Unexpected session value from empty context")
	}
	ctx = SetClientSessionToContext(ctx, session)
	value := ClientSessionFromContext(ctx)
	if !reflect.DeepEqual(value, session) {
		t.Fatal("Returned incorrect session value")
	}
}
