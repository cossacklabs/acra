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
	"errors"
	"go.opencensus.io/trace"
	"net"
)

// ConnectionTimeoutWrapper interface
type ConnectionTimeoutWrapper interface {
	net.Conn
}

// ConnectionMetadata connection metadata
type ConnectionMetadata interface {
	SpanContext() (trace.SpanContext, bool)
	ClientID() ([]byte, bool)
}

// ConnectionWrapper interface
type ConnectionWrapper interface {
	WrapClient(ctx context.Context, conn net.Conn) (net.Conn, error)
	WrapServer(ctx context.Context, conn net.Conn) (net.Conn, []byte, error) // conn, ClientID, error
}

var (
	// ErrCantExtractClientID used when can't extract ClientID from gRPC connection handshake
	ErrCantExtractClientID = errors.New("can't extract ClientID from gRPC connection")
	// ErrIncorrectGRPCConnectionAuthInfo used if gRPC connection AuthState has unsupported type
	ErrIncorrectGRPCConnectionAuthInfo = errors.New("incorrect auth info from gRPC connection")
)

// GRPCConnectionClientIDExtractor extract clientID from connection AuthInfo encapsulated in request context
type GRPCConnectionClientIDExtractor interface {
	ExtractClientID(context.Context) ([]byte, error)
}
