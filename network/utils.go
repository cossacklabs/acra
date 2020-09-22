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
	"fmt"
	"github.com/cossacklabs/themis/gothemis/errors"
	"net"
	url_ "net/url"
	"os"
	"strconv"
	"strings"
	"sync"
)

// Custom connection schemes, used in AcraConnector and AcraTranslator
const (
	GRPCScheme = "grpc"
	HTTPScheme = "http"
)

func customSchemeToBaseGolangScheme(scheme string) string {
	if scheme == GRPCScheme || scheme == HTTPScheme {
		return "tcp"
	}
	return scheme
}

// safeCloseConnection wrap connection and ensure that net.Conn.Close will be called only once
type safeCloseConnection struct {
	net.Conn
	once sync.Once
	err  error
}

// close proxy Close call and store error
func (conn *safeCloseConnection) close() {
	conn.err = conn.Conn.Close()
}

// Close connection only once and return error of first Close call
func (conn *safeCloseConnection) Close() error {
	conn.once.Do(conn.close)
	return conn.err
}

// newSafeCloseConnection wrap conn with safeCloseConnection
func newSafeCloseConnection(conn net.Conn) net.Conn {
	return &safeCloseConnection{Conn: conn}
}

// UnwrapSafeCloseConnection return wrapped Conn implementation or conn from parameter as is
func UnwrapSafeCloseConnection(conn net.Conn) net.Conn {
	if safeConn, ok := conn.(*safeCloseConnection); ok {
		return safeConn.Conn
	}
	return conn
}

// safeCloseListener ensure that Close method of wrapped listener will be called only once and wrap all accepted connections
// with safeCloseConnection
type safeCloseListener struct {
	net.Listener
	once sync.Once
	err  error
}

func newSafeCloseListener(l net.Listener) net.Listener {
	return &safeCloseListener{Listener: l}
}

// UnwrapSafeCloseListener return wrapped listener or listener from parameter as is
func UnwrapSafeCloseListener(listener net.Listener) net.Listener {
	if safeListener, ok := listener.(*safeCloseListener); ok {
		return safeListener.Listener
	}
	return listener
}

// close proxy Close call and store error
func (listener *safeCloseListener) close() {
	listener.err = listener.Listener.Close()
}

// Close listener only once and return error of first Close call
func (listener *safeCloseListener) Close() error {
	listener.once.Do(listener.close)
	return listener.err
}

var ErrNilListener = errors.New("nil listener")

// Accept proxy call to wrapped listener and wrap accepted connection with safeCloseConnection
func (listener *safeCloseListener) Accept() (net.Conn, error) {
	if listener.Listener != nil {
		conn, err := listener.Listener.Accept()
		return newSafeCloseConnection(conn), err
	}
	return nil, ErrNilListener
}

// Dial connectionString like protocol://path where protocol is any supported via net.Dial (tcp|unix)
func Dial(connectionString string) (net.Conn, error) {
	url, err := url_.Parse(connectionString)
	if err != nil {
		return nil, err
	}
	url.Scheme = customSchemeToBaseGolangScheme(url.Scheme)
	var conn net.Conn
	if url.Scheme == "unix" {
		conn, err = net.Dial(url.Scheme, url.Path)
	} else {
		conn, err = net.Dial(url.Scheme, url.Host)
	}
	return newSafeCloseConnection(conn), err
}

// ListenerWithFileDescriptor listens to file
type ListenerWithFileDescriptor interface {
	net.Listener
	File() (f *os.File, err error)
}

// Listen returns listener for connection string
func Listen(connectionString string) (net.Listener, error) {
	url, err := url_.Parse(connectionString)
	if err != nil {
		return nil, err
	}
	url.Scheme = customSchemeToBaseGolangScheme(url.Scheme)
	var listener net.Listener
	if url.Scheme == "unix" {
		listener, err = net.Listen(url.Scheme, url.Path)
	} else {
		listener, err = net.Listen(url.Scheme, url.Host)
	}
	return newSafeCloseListener(listener), err
}

// BuildConnectionString as <protocol>://<host>:<port>/<path>
func BuildConnectionString(protocol, host string, port int, path string) string {
	return fmt.Sprintf("%s://%s:%v/%s", protocol, host, port, path)
}

// ListenerFileDescriptor returns file descriptor if listener listens file
func ListenerFileDescriptor(socket net.Listener) (uintptr, error) {
	socket = UnwrapSafeCloseListener(socket)
	file, err := socket.(ListenerWithFileDescriptor).File()
	if err != nil {
		return 0, err
	}
	return file.Fd(), nil
}

// SNIOrHostname return sni value if != "". otherwise return hostname without port
func SNIOrHostname(sni, hostname string) string {
	if sni != "" {
		return sni
	}
	colonPos := strings.LastIndex(hostname, ":")
	if colonPos == -1 {
		colonPos = len(hostname)
	}
	return hostname[:colonPos]
}

// SplitConnectionString to host, port
func SplitConnectionString(connectionString string) (string, int, error) {
	url, err := url_.Parse(connectionString)
	if err != nil {
		return "", 0, err
	}
	if url.Scheme == "unix" {
		return "", 0, fmt.Errorf("can't split to host:port unix socket path <%s>", connectionString)
	}
	port, err := strconv.Atoi(url.Port())
	if err != nil {
		return "", 0, err
	}
	return url.Hostname(), port, nil
}
