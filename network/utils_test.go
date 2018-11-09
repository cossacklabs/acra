/*
Copyright 2018, Cossack Labs Limited

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
	"errors"
	"net"
	"testing"
	"time"
)

type testConnection struct {
	closeCount int
}

var errTestClose = errors.New("close test connection")

func (conn *testConnection) Close() error {
	conn.closeCount++
	if conn.closeCount == 1 {
		return errTestClose
	}
	return errors.New("unexpected error")
}

func (conn *testConnection) LocalAddr() net.Addr {
	panic("implement me")
}

func (conn *testConnection) Read(b []byte) (n int, err error) {
	panic("implement me")
}

func (conn *testConnection) RemoteAddr() net.Addr {
	panic("implement me")
}

func (conn *testConnection) SetDeadline(t time.Time) error {
	panic("implement me")
}

func (conn *testConnection) SetReadDeadline(t time.Time) error {
	panic("implement me")
}

func (conn *testConnection) SetWriteDeadline(t time.Time) error {
	panic("implement me")
}

func (conn *testConnection) Write(b []byte) (n int, err error) {
	panic("implement me")
}

// TestSafeCloseConnection check that connection wrapped with saveCloseConnection call only once conn.Close method and
// always return error from first call
func TestSafeCloseConnection(t *testing.T) {
	testConn := &testConnection{}
	conn := newSafeCloseConnection(testConn)
	err1 := conn.Close()
	err2 := conn.Close()
	if testConn.closeCount != 1 {
		t.Fatal("Close called more than once")
	}
	if err1 != errTestClose || err2 != errTestClose {
		t.Fatal("Close method return incorrect error")
	}
}
