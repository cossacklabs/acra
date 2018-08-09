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
