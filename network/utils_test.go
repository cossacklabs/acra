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

	"github.com/stretchr/testify/assert"
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

func TestGetDriverConnectionStringHost(t *testing.T) {
	t.Run("MySQL valid connection URL", func(t *testing.T) {
		url := "test:test@tcp(localhost:3306)/test"
		host, err := GetDriverConnectionStringHost(url, true)
		assert.NoError(t, err)
		assert.Equal(t, "localhost", host)
	})

	t.Run("MySQL valid connection URL & login with non-schema characters", func(t *testing.T) {
		url := "test_-test:test@tcp(localhost:3306)/test"
		host, err := GetDriverConnectionStringHost(url, true)
		assert.NoError(t, err)
		assert.Equal(t, "localhost", host)
	})

	t.Run("MySQL valid connection URL without credentials and protocol", func(t *testing.T) {
		url := "(localhost:3306)/test"
		host, err := GetDriverConnectionStringHost(url, true)
		assert.NoError(t, err)
		assert.Equal(t, "localhost", host)
	})

	t.Run("MySQL invalid connection URL", func(t *testing.T) {
		url := "test:test@tcp://localhost:3306/test"
		_, err := GetDriverConnectionStringHost(url, true)
		assert.Error(t, err)
	})

	t.Run("PostgreSQL invalid connection URL with useMySQL=true", func(t *testing.T) {
		url := "test:test@localhost:5432/test"
		_, err := GetDriverConnectionStringHost(url, true)
		assert.Error(t, err)
	})

	t.Run("PostgreSQL specific string with useMySQL=true", func(t *testing.T) {
		url := "postgresql://test:test@localhost:5432/test"
		_, err := GetDriverConnectionStringHost(url, true)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "default addr for network 'localhost:5432' unknown")
	})

	t.Run("PostgreSQL valid connection URL", func(t *testing.T) {
		url := "postgresql://test:test@localhost:5432/test"
		host, err := GetDriverConnectionStringHost(url, false)
		assert.NoError(t, err)
		assert.Equal(t, "localhost", host)
	})

	t.Run("PostgreSQL invalid connection URL", func(t *testing.T) {
		url := "test:test@localhost:5432/test"
		_, err := GetDriverConnectionStringHost(url, false)
		assert.Error(t, err)
	})

	t.Run("MySQL specific string with useMySQL=false", func(t *testing.T) {
		url := "test:test@tcp(localhost:3306)/test"
		_, err := GetDriverConnectionStringHost(url, false)
		assert.Error(t, err)
	})
}
