package network

import (
	"fmt"
	"net"
	url_ "net/url"
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

func Listen(connectionString string) (net.Listener, error){
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

func BuildConnectionString(protocol, host string, port int, path string)(string){
	return fmt.Sprintf("%s://%s:%v/%s", protocol, host, port, path)
}