package network

import (
	"fmt"
	"net"
	url_ "net/url"
	"os"
)

// Dial connectionString like protocol://path where protocol is any supported via net.Dial (tcp|unix)
func Dial(connectionString string) (net.Conn, error) {
	url, err := url_.Parse(connectionString)
	if err != nil {
		return nil, err
	}
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
