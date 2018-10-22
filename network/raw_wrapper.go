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
	"context"
	"net"
)

// RawConnectionWrapper doesn't add any encryption above connection
type RawConnectionWrapper struct {
	net.Conn
	ClientID []byte
}

// WrapClient returns RawConnectionWrapper above client connection
func (wrapper *RawConnectionWrapper) WrapClient(ctx context.Context, id []byte, conn net.Conn) (net.Conn, error) {
	wrapper.Conn = conn
	return conn, nil
}

// WrapServer returns RawConnectionWrapper above server connection
func (wrapper *RawConnectionWrapper) WrapServer(ctx context.Context, conn net.Conn) (net.Conn, []byte, error) {
	wrapper.Conn = conn
	return conn, wrapper.ClientID, nil
}
