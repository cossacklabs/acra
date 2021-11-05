package main

import (
	"net"
	"testing"
	"time"
)

type panicConnection struct {
	called bool
}

func (p *panicConnection) Read(b []byte) (n int, err error) {
	panic("implement me")
}

func (p *panicConnection) Write(b []byte) (n int, err error) {
	panic("implement me")
}

func (p *panicConnection) Close() error {
	panic("implement me")
}

func (p *panicConnection) LocalAddr() net.Addr {
	panic("implement me")
}

func (p *panicConnection) RemoteAddr() net.Addr {
	p.called = true
	panic("implement me")
}

func (p *panicConnection) SetDeadline(t time.Time) error {
	panic("implement me")
}

func (p *panicConnection) SetReadDeadline(t time.Time) error {
	panic("implement me")
}

func (p *panicConnection) SetWriteDeadline(t time.Time) error {
	panic("implement me")
}

func TestRecovery(t *testing.T) {
	config := &Config{DisableUserCheck: false}
	conn := &panicConnection{}
	for _, fun := range []func(*Config, net.Conn){handleClientConnection, handleAPIConnection} {
		fun(config, conn)
		if !conn.called {
			t.Fatal("Wasn't call panic")
		}
		conn.called = false
		// call second time to be sure that recovered after panic
		fun(config, conn)
		if !conn.called {
			t.Fatal("Wasn't call panic")
		}
		conn.called = false
	}
}
