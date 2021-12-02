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
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"github.com/cossacklabs/acra/keystore"
	"io/ioutil"
	math_rand "math/rand"
	"net"
	"os"
	"testing"
	"time"
)

// wrapperCommunicationIterations base iterations count which may be used in a communication loop using client/server wrappers
const wrapperCommunicationIterations = 10

func getUnixListenerAndConnection(t testing.TB) (net.Listener, net.Conn) {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(f.Name()); err != nil {
		t.Fatal(err)
	}
	socket := f.Name()
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		connection.Close()
		os.Remove(f.Name())
		listener.Close()
	})
	return listener, connection
}

func getTCPListenerAndConnection(t testing.TB) (net.Listener, net.Conn) {
	listener, err := net.ListenTCP("tcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal()
	}
	t.Cleanup(func() {
		listener.Close()
		conn.Close()
	})
	return listener, conn
}

// testWrapper wrapper over testWrapperWithError with onError callback which call t.Fatal on err value
func testWrapper(clientWrapper, serverWrapper ConnectionWrapper, expectedClientID []byte, iterations int, t testing.TB) {
	onError := func(err error, t testing.TB) { t.Fatal(err) }
	unixListener, unixConnection := getUnixListenerAndConnection(t)
	testWrapperWithSpecifiedProtocol(unixListener, unixConnection, clientWrapper, serverWrapper, expectedClientID, iterations, onError, t)
	tcpListener, tcpConnection := getTCPListenerAndConnection(t)
	testWrapperWithSpecifiedProtocol(tcpListener, tcpConnection, clientWrapper, serverWrapper, expectedClientID, iterations, onError, t)
}

func testWrapperWithError(clientWrapper, serverWrapper ConnectionWrapper, expectedClientID []byte, iterations int, onError func(error, testing.TB), t testing.TB) {
	unixListener, unixConnection := getUnixListenerAndConnection(t)
	testWrapperWithSpecifiedProtocol(unixListener, unixConnection, clientWrapper, serverWrapper, expectedClientID, iterations, onError, t)
}

// testWrapperWithSpecifiedProtocol use provided listener and connection, wrap them using clientWrapper and serverWrapper,
// verify received clientID on server side with expected and exchange some data iterations times.
// On any unexpected error call onError callback
func testWrapperWithSpecifiedProtocol(listener net.Listener, connection net.Conn, clientWrapper, serverWrapper ConnectionWrapper, expectedClientID []byte, iterations int, onError func(error, testing.TB), t testing.TB) {
	// use ctx to force background listener in goroutine wait finishing this function
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const bufSize = 1024

	go func(ctx context.Context) {
		buf := make([]byte, bufSize)
		conn, err := listener.Accept()
		if err != nil {
			conn.Close()
			onError(err, t)
			return
		}
		defer conn.Close()
		wrappedConn, clientID, err := serverWrapper.WrapServer(context.TODO(), conn)
		if err != nil {
			onError(err, t)
			return
		}
		defer wrappedConn.Close()
		if !bytes.Equal(clientID, expectedClientID) {
			onError(keystore.ErrInvalidClientID, t)
			return
		}
		for i := 0; i < iterations; i++ {
			n, err := wrappedConn.Read(buf)
			if err != nil {
				onError(err, t)
				return
			}
			_, err = wrappedConn.Write(buf[:n])
			if err != nil {
				onError(err, t)
				return
			}
		}
		<-ctx.Done()
	}(ctx)
	var err error
	connection, err = clientWrapper.WrapClient(context.TODO(), connection)
	if err != nil {
		onError(err, t)
	}

	clientBuf := make([]byte, bufSize)
	dataBuf := make([]byte, bufSize)
	math_rand.Seed(time.Now().UnixNano())
	for i := 0; i < iterations; i++ {
		// always write different amount of data
		dataLength := 1 + (math_rand.Int31() % (bufSize - 1))
		_, err := rand.Read(dataBuf[:dataLength])
		if err != nil {
			onError(err, t)
		}
		_, err = connection.Write(dataBuf[:dataLength])
		if err != nil {
			connection.Close()
			onError(err, t)
		}
		n, err := connection.Read(clientBuf)
		if err != nil {
			connection.Close()
			onError(err, t)
		}
		if result := bytes.Compare(clientBuf[:n], dataBuf[:dataLength]); result != 0 {
			connection.Close()
			onError(errors.New("data not equal"), t)
		}
	}
}

type invalidAuthInfo struct{}

func (i invalidAuthInfo) AuthType() string {
	panic("implement me")
}

func testTLSGRPCClientIDExtractorIncorrectAuthInfo(t *testing.T) {
	resultClientID, err := GetClientIDFromAuthInfo(invalidAuthInfo{}, nil)
	if err != ErrCantExtractClientID {
		t.Fatal(err)
	}
	if resultClientID != nil {
		t.Fatal("ClientID != nil")
	}
}
