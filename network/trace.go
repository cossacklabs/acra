/*
Copyright 2018, Cossack Labs Limited

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
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
	"go.opencensus.io/trace/propagation"
	"net"
)

// ErrContextWithoutTrace error if context.Context hasn't any trace.Span
var ErrContextWithoutTrace = errors.New("context hasn't any trace")

// SendTrace fetch span from context and propagate it to conn as binary data. If context doesn't contain trace then ErrContextWithoutTrace return
func SendTrace(ctx context.Context, conn net.Conn) error {
	span := trace.FromContext(ctx)
	if span == nil {
		return ErrContextWithoutTrace
	}
	binContext := propagation.Binary(span.SpanContext())
	return utils.SendData(binContext, conn)
}

// ReadTrace read trace from conn and return
func ReadTrace(conn net.Conn) (trace.SpanContext, error) {
	binContext, err := utils.ReadData(conn)
	if err != nil {
		return trace.SpanContext{}, err
	}
	spanContext, _ := propagation.FromBinary(binContext)
	return spanContext, nil
}

type traceConnection struct {
	net.Conn
	spanContext trace.SpanContext
}

// Unwrap return wrapped connection
func (conn *traceConnection) Unwrap() net.Conn {
	return conn.Conn
}

// GetSpanContextFromConnection extract trace.SpanContext from connections if it's safeCloseConnection otherwise trace.SpanContext{}, false
func GetSpanContextFromConnection(conn net.Conn) (trace.SpanContext, bool) {
	// unwrap until find connectionWithMetadata or return false if it's pure net.Conn
	for {
		unwrapped, ok := conn.(WrappedConnection)
		if !ok {
			return trace.SpanContext{}, false
		}
		if connWithMetadata, ok := unwrapped.(*traceConnection); ok {
			return connWithMetadata.spanContext, true
		}
		conn = unwrapped.Unwrap()
	}
}

// TraceConnectionCallback read and wrap connection with trace info
type TraceConnectionCallback struct{}

// OnConnectionContext read trace and store it in context
func (cb TraceConnectionCallback) OnConnectionContext(ctx context.Context, c net.Conn) (context.Context, error) {
	log.Debugln("Wrap connection with trace info")
	traceCtx, err := ReadTrace(c)
	if err != nil {
		return ctx, err
	}
	// same options as for acra-server
	options := []trace.StartOption{trace.WithSpanKind(trace.SpanKindServer), trace.WithSampler(trace.AlwaysSample())}
	ctx, _ = trace.StartSpanWithRemoteParent(ctx, "HTTPApiConnection", traceCtx, options...)
	return ctx, nil
}

// OnServerHandshake wrap conn with trace information
func (TraceConnectionCallback) OnServerHandshake(conn net.Conn) (net.Conn, error) {
	ctx, err := ReadTrace(conn)
	if err != nil {
		return conn, err
	}
	return &traceConnection{Conn: conn, spanContext: ctx}, nil
}
