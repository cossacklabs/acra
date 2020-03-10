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

type traceWrapper struct {
	wrapper ConnectionWrapper
}

func NewTraceConnectionWrapper(wrapper ConnectionWrapper) (*traceWrapper, error) {
	return &traceWrapper{wrapper}, nil
}

func (t *traceWrapper) WrapClient(ctx context.Context, conn net.Conn) (net.Conn, error) {
	wrappedConn, err := t.wrapper.WrapClient(ctx, conn)
	if err != nil {
		return nil, err
	}
	if err := SendTrace(ctx, wrappedConn); err != nil {
		return nil, err
	}
	return wrappedConn, nil
}

func (t *traceWrapper) WrapServer(ctx context.Context, conn net.Conn) (net.Conn, []byte, error) {
	wrappedConn, id, err := t.wrapper.WrapServer(ctx, conn)
	if err != nil {
		return nil, nil, err
	}
	_, err = ReadTrace(wrappedConn)
	if err != nil {
		return nil, nil, err
	}
	return wrappedConn, id, nil
}
