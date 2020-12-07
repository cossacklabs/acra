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
	"net"
	"os"
	"testing"
)

// wrapperCommunicationIterations base iterations count which may be used in a communication loop using client/server wrappers
const wrapperCommunicationIterations = 10

// testWrapper wrapper over testWrapperWithError with onError callback which call t.Fatal on err value
func testWrapper(clientWrapper, serverWrapper ConnectionWrapper, expectedClientID []byte, iterations int, t testing.TB) {
	onError := func(err error, t testing.TB) { t.Fatal(err) }
	testWrapperWithError(clientWrapper, serverWrapper, expectedClientID, iterations, onError, t)
}

// testWrapperWithError create unix socket, wrap it using clientWrapper and serverWrapper, verify received clientID on server side with expected
// and exchange some data iterations times. On any unexpected error call onError callback
func testWrapperWithError(clientWrapper, serverWrapper ConnectionWrapper, expectedClientID []byte, iterations int, onError func(error, testing.TB), t testing.TB) {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		onError(err, t)
	}
	os.Remove(f.Name())
	socket := f.Name()
	listener, err := net.Listen("unix", socket)
	if err != nil {
		onError(err, t)
	}
	const bufSize = 1024
	defer listener.Close()
	go func() {
		buf := make([]byte, bufSize)
		conn, err := listener.Accept()
		if err != nil {
			conn.Close()
			onError(err, t)
			return
		}
		wrappedConn, clientID, err := serverWrapper.WrapServer(context.TODO(), conn)
		if err != nil {
			conn.Close()
			onError(err, t)
			return
		}
		if !bytes.Equal(clientID, expectedClientID) {
			conn.Close()
			onError(keystore.ErrInvalidClientID, t)
			return
		}
		for i := 0; i < iterations; i++ {
			n, err := wrappedConn.Read(buf)
			if err != nil {
				wrappedConn.Close()
				onError(err, t)
				return
			}
			_, err = wrappedConn.Write(buf[:n])
			if err != nil {
				wrappedConn.Close()
				onError(err, t)
			}
		}
	}()

	connection, err := net.Dial("unix", socket)
	if err != nil {
		onError(err, t)
	}
	defer connection.Close()
	connection, err = clientWrapper.WrapClient(context.TODO(), connection)
	if err != nil {
		onError(err, t)
	}

	clientBuf := make([]byte, bufSize)
	dataBuf := make([]byte, bufSize)
	for i := 0; i < iterations; i++ {
		_, err := rand.Read(dataBuf)
		if err != nil {
			onError(err, t)
		}
		_, err = connection.Write(dataBuf)
		if err != nil {
			connection.Close()
			onError(err, t)
		}
		_, err = connection.Read(clientBuf)
		if err != nil {
			connection.Close()
			onError(err, t)
		}
		if result := bytes.Compare(clientBuf, dataBuf); result != 0 {
			connection.Close()
			onError(errors.New("data not equal"), t)
		}
	}
}
