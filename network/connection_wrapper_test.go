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
	"crypto/tls"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cossacklabs/themis/gothemis/keys"
	"strings"
)

var TestClientID = []byte("client")
var TestServerID = []byte("server")

func wait(ch chan bool, t *testing.T) {
	select {
	case val := <-ch:
		if !val {
			t.Fatal("some err")
			os.Exit(1)
		}
	case <-time.Tick(time.Second * 100):
		t.Fatal("timeout")
		os.Exit(1)
	}
}

func testWrapper(clientWrapper, serverWrapper ConnectionWrapper, t *testing.T) {
	const iterations = 10
	socket := "/tmp/testWrapper"
	os.Remove(socket)
	clientCh := make(chan bool)
	serverCh := make(chan bool)
	go func() {
		buf := make([]byte, 1000)
		t.Log("listen")
		listener, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		clientCh <- true
		t.Log("accept")
		conn, err := listener.Accept()
		if err != nil {
			conn.Close()
			t.Fatal(err)
			return
		}
		t.Log("wrap server")
		conn, clientID, err := serverWrapper.WrapServer(context.TODO(), conn)
		if err != nil {
			conn.Close()
			t.Fatal(err)
			return
		}
		if !bytes.Equal(clientID, TestClientID) {
			t.Fatal("client id incorrect")
		}
		for i := 0; i < iterations; i++ {
			t.Log("wait server read")
			wait(serverCh, t)
			n, err := conn.Read(buf)
			if err != nil {
				conn.Close()
				t.Fatal(err)
				return
			}
			t.Log("server write")
			_, err = conn.Write(buf[:n])
			if err != nil {
				clientCh <- false
				conn.Close()
				t.Fatal(err)
			}
			clientCh <- true
		}
		t.Log("wait server to close")
		// wait when client read last packet
		if !<-serverCh {
			return
		}
	}()

	t.Log("client wait to connect")
	wait(clientCh, t)
	t.Log("client connect")
	connection, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	t.Log("wrap client")
	connection, err = clientWrapper.WrapClient(context.TODO(), TestServerID, connection)
	if err != nil {
		connection.Close()
		t.Fatal(err)
	}

	clientBuf := make([]byte, 1024)
	for i := 0; i < iterations; i++ {
		data := append([]byte("some data"), byte(i))
		t.Log("client write")
		_, err := connection.Write(data)
		if err != nil {
			connection.Close()
			t.Fatal(err)
		}
		serverCh <- true
		t.Log("client wait to read")
		wait(clientCh, t)
		n, err := connection.Read(clientBuf)
		if err != nil {
			connection.Close()
			t.Fatal(err)
		}
		if !bytes.Equal(clientBuf[:n], data) {
			connection.Close()
			t.Fatal("data not equal")
		}
	}
	serverCh <- true
}

func TestRawConnectionWrapper(t *testing.T) {
	testWrapper(&RawConnectionWrapper{}, &RawConnectionWrapper{ClientID: TestClientID}, t)
}

type SimpleKeyStore struct {
	PrivateKey *keys.PrivateKey
	PublicKey  *keys.PublicKey
}

func (keystore *SimpleKeyStore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	return keystore.PrivateKey, nil
}
func (keystore *SimpleKeyStore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	return keystore.PublicKey, nil
}

func TestSessionWrapper(t *testing.T) {
	clientPair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		t.Fatal(err)
	}
	serverPair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		t.Fatal(err)
	}
	clientWrapper, err := NewSecureSessionConnectionWrapper(TestClientID, &SimpleKeyStore{PrivateKey: clientPair.Private, PublicKey: serverPair.Public})
	if err != nil {
		t.Fatal(err)
	}
	serverWrapper, err := NewSecureSessionConnectionWrapper(TestServerID, &SimpleKeyStore{PrivateKey: serverPair.Private, PublicKey: clientPair.Public})
	if err != nil {
		t.Fatal(err)
	}
	testWrapper(clientWrapper, serverWrapper, t)
}

func TestTLSWRapper(t *testing.T) {
	// openssl ecparam -genkey -name secp384r1 -out server.key
	// openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
	// cat server.key
	// cat server.cert
	key := []byte(`
-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAr0pCdkWNZrTUj+ps6Geykc+9XbMvJvt9SwLcZ4GlmUtF2d1bFSVE3
53QpZSC3VUqgBwYFK4EEACKhZANiAARBt0OyuQE23jR6N7laliQcno2zUjQry8bL
99YStj7fPELLSbW0usiOocLPx2dXrLquStjrsuzNNgJWtGfUttrZIYG3U9e4YxP2
Om/FTC3VwwAePSjKCOpVLh2FUyXcIxE=
-----END EC PRIVATE KEY-----
`)
	cert := []byte(`
-----BEGIN CERTIFICATE-----
MIICMDCCAbWgAwIBAgIJAIF7CJa9LIURMAoGCCqGSM49BAMCMFQxCzAJBgNVBAYT
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQxDTALBgNVBAMMBHRlc3QwHhcNMTgwMjE1MTMwNjAyWhcNMjgw
MjEzMTMwNjAyWjBUMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEh
MB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQ0wCwYDVQQDDAR0ZXN0
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQbdDsrkBNt40eje5WpYkHJ6Ns1I0K8vG
y/fWErY+3zxCy0m1tLrIjqHCz8dnV6y6rkrY67LszTYCVrRn1Lba2SGBt1PXuGMT
9jpvxUwt1cMAHj0oygjqVS4dhVMl3CMRo1MwUTAdBgNVHQ4EFgQURCzCHTN9WG1C
BfEWHrAaZwCDAjkwHwYDVR0jBBgwFoAURCzCHTN9WG1CBfEWHrAaZwCDAjkwDwYD
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNpADBmAjEA+2dZHMY3yI+0BPqytyCt
E0B2xKAzGuMumud6IbYpoIk3uj7bjfeejSyZPgxIOkEPAjEA+adYfhHGieUnnC26
Mmsz2rgkLFqKpYS30+CYbzwIXMfHImhBX2kO9HkodBWvNApu
-----END CERTIFICATE-----
`)
	clientConfig, err := NewTLSConfig("", "", "", "", tls.NoClientCert)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.InsecureSkipVerify = true
	clientWrapper, err := NewTLSConnectionWrapper(nil, clientConfig)
	if err != nil {
		t.Fatal(err)
	}

	cer, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
		return
	}

	serverConfig, err := NewTLSConfig("", "", "", "", tls.NoClientCert)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig.Certificates = []tls.Certificate{cer}
	serverWrapper, err := NewTLSConnectionWrapper(TestClientID, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	testWrapper(clientWrapper, serverWrapper, t)

	testTLSConfig(serverWrapper, t)
}

func getConnectionPair(address string, listener net.Listener, t *testing.T) (net.Conn, net.Conn) {
	serverConnCh := make(chan net.Conn)
	clientConnCh := make(chan net.Conn)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		serverConnCh <- conn
	}()
	go func() {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		clientConnCh <- conn
	}()
	// wait when client connect to server
	var clientConn, serverConn net.Conn
	for i := 0; i < 2; i++ {
		select {
		case clientConn = <-clientConnCh:
			continue
		case serverConn = <-serverConnCh:
			continue
		case <-time.NewTimer(time.Second / 2).C:
			t.Fatal("Timeout on connection client with server")
		}
	}
	return clientConn, serverConn
}

func testTLSConfig(serverWrapper *TLSConnectionWrapper, t *testing.T) {
	const address = "127.0.0.1:4567"
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}

	clientConn, serverConn := getConnectionPair(address, listener, t)

	wrapErrorCh := make(chan bool)
	// check not allowed cipher suit
	config, err := NewTLSConfig("", "", "", "", tls.NoClientCert)
	if err != nil {
		t.Fatal(err)
	}
	config.InsecureSkipVerify = true
	config.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256}
	clientWrapper, err := NewTLSConnectionWrapper([]byte("some client"), config)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _, err := serverWrapper.WrapServer(context.TODO(), serverConn)
		if err != nil {
			if err.Error() != "tls: no cipher suite supported by both client and server" {
				t.Fatal("Expected error with unsupported ciphersuits")
			}
			wrapErrorCh <- true
			return
		}
		t.Fatal("expected error")
	}()
	go func() {
		_, err := clientWrapper.WrapClient(context.TODO(), []byte("server"), clientConn)
		if err != nil {
			if err.Error() != "remote error: tls: handshake failure" {
				t.Fatal("Expected with handshake failure")
			}
			wrapErrorCh <- true
			return
		}
		t.Fatal("expected error")
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-wrapErrorCh:
			continue
		case <-time.NewTimer(time.Second / 2).C:
			t.Fatal("Timeout on wrap with incorrect cipher suits")
		}
	}
	if err := clientConn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.Close(); err != nil {
		t.Fatal(err)
	}

	// check not allowed protocol version
	clientConn, serverConn = getConnectionPair(address, listener, t)
	config, err = NewTLSConfig("", "", "", "", tls.NoClientCert)
	if err != nil {
		t.Fatal(err)
	}
	config.InsecureSkipVerify = true
	config.MinVersion = tls.VersionSSL30
	config.MaxVersion = tls.VersionTLS11
	clientWrapper, err = NewTLSConnectionWrapper([]byte("some client"), config)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _, err := serverWrapper.WrapServer(context.TODO(), serverConn)
		if err != nil {
			// error has concatenated protocol version at end of string and we doesn't need to compare as equality
			if !strings.HasPrefix(err.Error(), "tls: client offered an unsupported, maximum protocol version of") {
				t.Fatal("Expected incorrect protocol version error")
			}
			wrapErrorCh <- true
			return
		}
		t.Fatal("expected error")
	}()
	go func() {
		_, err := clientWrapper.WrapClient(context.TODO(), []byte("server"), clientConn)
		if err != nil {
			if err.Error() != "remote error: tls: protocol version not supported" {
				t.Fatal("Expected incorrect protocol version error")
			}
			wrapErrorCh <- true
			return
		}
		t.Fatal("expected error")
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-wrapErrorCh:
			continue
		case <-time.NewTimer(time.Second / 2).C:
			t.Fatal("Timeout on wrap with unsupported protocol version")
		}
	}
	if err := clientConn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.Close(); err != nil {
		t.Fatal(err)
	}
}
