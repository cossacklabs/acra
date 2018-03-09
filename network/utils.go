package network

import (
	"fmt"
	"net"
	url_ "net/url"
	"strconv"
	"strings"
	"errors"
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

func ListenTCP(connectionString string) (*net.TCPListener, error) {
	url, err := url_.Parse(connectionString)
	if err != nil {
		return nil, err
	}
	i := strings.LastIndex(url.Host, ":")
	if i < 0 {
		return nil, errors.New("no port")
	}
	port, _ := strconv.Atoi(url.Host[i+1:])

	if url.Scheme == "unix" {
		return nil, nil
	} else {
		return net.ListenTCP(url.Scheme, &net.TCPAddr{IP: net.ParseIP(url.Host), Port: port})
	}
}

func BuildConnectionString(protocol, host string, port int, path string) string {
	return fmt.Sprintf("%s://%s:%v/%s", protocol, host, port, path)
}
