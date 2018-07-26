// Package network contains network utils for establishing secure session, for listening connections.
//
package network

import (
	"fmt"
	"net"
	url_ "net/url"
	"os"
	"strings"
)

// Custom connection schemes, used in AcraConnector and AcraTranslator
const (
	GRPC_SCHEME = "grpc"
	HTTP_SCHEME = "http"
)

func customSchemeToBaseGolangScheme(scheme string) string {
	if scheme == GRPC_SCHEME || scheme == HTTP_SCHEME {
		return "tcp"
	}
	return scheme
}

// Dial connectionString like protocol://path where protocol is any supported via net.Dial (tcp|unix)
func Dial(connectionString string) (net.Conn, error) {
	url, err := url_.Parse(connectionString)
	if err != nil {
		return nil, err
	}
	url.Scheme = customSchemeToBaseGolangScheme(url.Scheme)
	if url.Scheme == "unix" {
		return net.Dial(url.Scheme, url.Path)
	}
	return net.Dial(url.Scheme, url.Host)
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
	if url.Scheme == "unix" {
		return net.Listen(url.Scheme, url.Path)
	}
	return net.Listen(url.Scheme, url.Host)
}

// BuildConnectionString as <protocol>://<host>:<port>/<path>
func BuildConnectionString(protocol, host string, port int, path string) string {
	return fmt.Sprintf("%s://%s:%v/%s", protocol, host, port, path)
}

// ListenerFileDescriptor returns file descriptor if listener listens file
func ListenerFileDescriptor(socket net.Listener) (uintptr, error) {
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
