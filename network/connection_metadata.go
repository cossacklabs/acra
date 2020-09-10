/*
Copyright 2020, Cossack Labs Limited

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

import "go.opencensus.io/trace"

// ConnectionMetadataBuilder builds connection metadata
type ConnectionMetadataBuilder struct {
	clientID []byte
	// opencensus uses and pass SpanContext by value everywhere to avoid problems with sharing state between thread
	// but we store pointer to simplify check is SpanContext was set or not by comparing with nil and return copy if need
	spanContext *trace.SpanContext
}

// NewConnectionMetadataBuilder return ConnectionMetadataBuilder which build ConnectionMetadata implementation
func NewConnectionMetadataBuilder() (*ConnectionMetadataBuilder, error) {
	return &ConnectionMetadataBuilder{}, nil
}

// SetClientID set client id
func (builder *ConnectionMetadataBuilder) SetClientID(c []byte) *ConnectionMetadataBuilder {
	builder.clientID = c
	return builder
}

// SetSpanContext set SpanContext
func (builder *ConnectionMetadataBuilder) SetSpanContext(c trace.SpanContext) *ConnectionMetadataBuilder {
	builder.spanContext = &c
	return builder
}

// ClientID return ClientID
func (builder *ConnectionMetadataBuilder) ClientID() ([]byte, bool) {
	return builder.clientID, builder.clientID != nil
}

// SpanContext return SpanContext and true if was set otherwise default SpanContext and false
func (builder *ConnectionMetadataBuilder) SpanContext() (trace.SpanContext, bool) {
	return *builder.spanContext, builder.spanContext != nil
}
