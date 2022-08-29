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

package base

import (
	"context"
)

// AccessContext store attributes which may be used for access policies and data manipulations
type AccessContext struct {
	clientID   []byte
	columnInfo ColumnInfo
}

// AccessContextOption function used to configure AccessContext struct
type AccessContextOption func(accessContext *AccessContext)

// WithClientID set clientID to AccessContext
func WithClientID(clientID []byte) AccessContextOption {
	return func(ctx *AccessContext) {
		ctx.clientID = clientID
	}
}

// NewAccessContext create new AccessContext and apply all options. Uses sync.Pool and require releasing by FreeAccessContext
func NewAccessContext(options ...AccessContextOption) *AccessContext {
	ctx := &AccessContext{}
	for _, option := range options {
		option(ctx)
	}
	return ctx
}

// SetClientID set new ClientID
func (ctx *AccessContext) SetClientID(clientID []byte) {
	ctx.clientID = clientID
}

// SetColumnInfo set ColumnInfo
func (ctx *AccessContext) SetColumnInfo(info ColumnInfo) {
	ctx.columnInfo = info
}

// OnNewClientID set new clientID and implements ClientIDObserver interface
func (ctx *AccessContext) OnNewClientID(clientID []byte) {
	ctx.clientID = clientID
}

// GetClientID return ClientID
func (ctx *AccessContext) GetClientID() []byte {
	return ctx.clientID
}

// GetColumnInfo return ColumnInfo
func (ctx *AccessContext) GetColumnInfo() ColumnInfo {
	return ctx.columnInfo
}

type accessContextKey struct{}

// SetAccessContextToContext save accessContext to ctx
func SetAccessContextToContext(ctx context.Context, accessContext *AccessContext) context.Context {
	return context.WithValue(ctx, accessContextKey{}, accessContext)
}

// AccessContextFromContext return AccessContext from ctx or new generated
func AccessContextFromContext(ctx context.Context) *AccessContext {
	value, ok := ctx.Value(accessContextKey{}).(*AccessContext)
	if ok {
		return value
	}
	return &AccessContext{}
}
