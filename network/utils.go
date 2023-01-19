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
	"flag"
	"fmt"
	"net"
	url_ "net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/cossacklabs/themis/gothemis/errors"
	log "github.com/sirupsen/logrus"
)

// Custom connection schemes, used in AcraTranslator
const (
	GRPCScheme = "grpc"
	HTTPScheme = "http"
)

// SafeCloseConnectionCallback callback that wraps connections with connection that call Close only once
type SafeCloseConnectionCallback struct{}

// OnConnection wraps connection with connection that call Close only once
func (SafeCloseConnectionCallback) OnConnection(conn net.Conn) (net.Conn, error) {
	log.Debugln("Wrap connection with safe close connection")
	return newSafeCloseConnection(conn), nil
}

// OnServerHandshake wrap conn with SafeCloseeConnection
func (SafeCloseConnectionCallback) OnServerHandshake(conn net.Conn) (net.Conn, error) {
	return newSafeCloseConnection(conn), nil
}

func customSchemeToBaseGolangScheme(scheme string) string {
	if scheme == GRPCScheme || scheme == HTTPScheme {
		return "tcp"
	}
	return scheme
}

// safeCloseConnection wrap connection and ensure that net.Conn.Close will be called only once, allow to store clientID
// and transferred SpanContext
type safeCloseConnection struct {
	net.Conn
	once sync.Once
	err  error
}

// Unwrap returns wrapped connection
func (conn *safeCloseConnection) Unwrap() net.Conn {
	return conn.Conn
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
	for {
		if safeListener, ok := listener.(*safeCloseListener); ok {
			return safeListener.Listener
		}
		unwrapped, ok := listener.(ListenerWrapper)
		if ok {
			listener = unwrapped.Unwrap()
			continue
		}
		return listener
	}
}

// Unwrap returns wrapped listener
func (listener *safeCloseListener) Unwrap() net.Listener {
	return listener.Listener
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

// ErrNilListener used if listener is nil
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
	log.WithField("sni", hostname[:colonPos]).Infoln("Use sni")
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

// IsFlagSet returns true if flag explicitly set via CLI arguments
// Don't move it to the cmd package due to import cycle
func isFlagSet(name string, flagset *flag.FlagSet) bool {
	set := false
	flagset.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// GetDBURLHost return DB host from MySQL/PostgreSQL connection string to use as SNI
// PostgreSQL - postgresql://{user}:{password}@{host}:{port}/{dbname}
// MySQL - ({user}:{password}@tcp({host}:{port})/{dbname}
func GetDBURLHost(connectionString string, useMySQL bool) (string, error) {
	connectionURL, err := url_.Parse(connectionString)
	if err != nil {
		return "", err
	}

	var hostPortURL = connectionURL.Host

	if useMySQL {
		hostPortStartIdx := strings.Index(connectionURL.Opaque, "(")
		hostPortEndIdx := strings.Index(connectionURL.Opaque, ")")

		if hostPortStartIdx == 0 || hostPortEndIdx == 0 || hostPortEndIdx <= hostPortStartIdx {
			return "", errors.New("invalid MySQL connectionURL")
		}

		hostPortURL = connectionURL.Opaque[hostPortStartIdx+1 : hostPortEndIdx]
	}

	if hostPortURL == "" {
		return "", errors.New("invalid connectionURL: expect not empty host:port")
	}

	host, _, err := net.SplitHostPort(hostPortURL)
	return host, err
}
