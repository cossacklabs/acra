package network

import (
	"errors"
	"fmt"
	"net"
	url_ "net/url"
	"os"
	"strings"
)

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
	} else {
		return net.Dial(url.Scheme, url.Host)
	}
}

type ListenerWithFileDescriptor interface {
	net.Listener
	File() (f *os.File, err error)
}

func Listen(connectionString string) (net.Listener, error) {
	url, err := url_.Parse(connectionString)
	if err != nil {
		return nil, err
	}
	url.Scheme = customSchemeToBaseGolangScheme(url.Scheme)
	if url.Scheme == "unix" {
		return net.Listen(url.Scheme, url.Path)
	} else {
		return net.Listen(url.Scheme, url.Host)
	}
}

func BuildConnectionString(protocol, host string, port int, path string) string {
	return fmt.Sprintf("%s://%s:%v/%s", protocol, host, port, path)
}

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

var ErrUnsupportedConnectionType = errors.New("unsupported net.Conn implementation")

// GetConnectionDescriptor return descriptor of connection or GetConnectionDescriptor
func GetConnectionDescriptor(connection net.Conn) (uintptr, error) {
	var file *os.File
	var err error
	switch connection.(type) {
	case *net.UDPConn:
		file, err = connection.(*net.UDPConn).File()
	case *net.IPConn:
		file, err = connection.(*net.IPConn).File()
	case *net.TCPConn:
		file, err = connection.(*net.TCPConn).File()
	case *net.UnixConn:
		file, err = connection.(*net.UnixConn).File()
	default:
		return 0, ErrUnsupportedConnectionType
	}
	if err != nil {
		return 0, err
	}
	return file.Fd(), err
}
