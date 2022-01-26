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
	"fmt"
	"github.com/cossacklabs/acra/network"
	"net"

	acracensor "github.com/cossacklabs/acra/acra-censor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/sqlparser"
)

// Callback represents function to call on detecting poison record
type Callback interface {
	Call() error
}

// PoisonRecordCallbackStorage stores all callbacks, on Call iterates
// and calls each callbacks until error or end of iterating
type PoisonRecordCallbackStorage interface {
	Callback
	AddCallback(callback Callback)
	HasCallbacks() bool
}

// ProxySetting provide data access methods for proxy factories
type ProxySetting interface {
	PoisonRecordCallbackStorage() PoisonRecordCallbackStorage
	SQLParser() *sqlparser.Parser
	KeyStore() keystore.DecryptionKeyStore
	TableSchemaStore() config.TableSchemaStore
	Censor() acracensor.AcraCensorInterface
	TLSConnectionWrapper() TLSConnectionWrapper
	WithZone() bool
}

type proxySetting struct {
	keystore                    keystore.DecryptionKeyStore
	tableSchemaStore            config.TableSchemaStore
	censor                      acracensor.AcraCensorInterface
	connectionWrapper           TLSConnectionWrapper
	poisonRecordCallbackStorage PoisonRecordCallbackStorage
	parser                      *sqlparser.Parser
	withZone                    bool
}

// SQLParser return sqlparser.Parser
func (p *proxySetting) SQLParser() *sqlparser.Parser {
	return p.parser
}

// PoisonRecordCallbackStorage return CallbackStorage
func (p *proxySetting) PoisonRecordCallbackStorage() PoisonRecordCallbackStorage {
	return p.poisonRecordCallbackStorage
}

// Censor return AcraCensorInterface implementation
func (p *proxySetting) Censor() acracensor.AcraCensorInterface {
	return p.censor
}

// TableSchemaStore return table schema store
func (p *proxySetting) TableSchemaStore() config.TableSchemaStore {
	return p.tableSchemaStore
}

// KeyStore return keystore
func (p *proxySetting) KeyStore() keystore.DecryptionKeyStore {
	return p.keystore
}

// TLSConnectionWrapper return TLSConnectionWrapper
func (p *proxySetting) TLSConnectionWrapper() TLSConnectionWrapper {
	return p.connectionWrapper
}

// WithZone return is turned on zonemode or not
func (p *proxySetting) WithZone() bool {
	return p.withZone
}

// NewProxySetting return new ProxySetting implementation with data from params
func NewProxySetting(parser *sqlparser.Parser, tableSchema config.TableSchemaStore, keystore keystore.DecryptionKeyStore, wrapper TLSConnectionWrapper, censor acracensor.AcraCensorInterface, callbackStorage PoisonRecordCallbackStorage, zoneMode bool) ProxySetting {
	return &proxySetting{keystore: keystore, parser: parser, tableSchemaStore: tableSchema, censor: censor, connectionWrapper: wrapper, poisonRecordCallbackStorage: callbackStorage, withZone: zoneMode}
}

// Proxy interface to process client's requests to database and responses
type Proxy interface {
	QueryObservable
	ClientIDObservable
	ProxyClientConnection(context.Context, chan<- ProxyError)
	ProxyDatabaseConnection(context.Context, chan<- ProxyError)
}

// ClientSession is a connection between the client and the database, mediated by AcraServer.
type ClientSession interface {
	Context() context.Context
	ClientConnection() net.Conn
	DatabaseConnection() net.Conn

	PreparedStatementRegistry() PreparedStatementRegistry
	SetPreparedStatementRegistry(registry PreparedStatementRegistry)

	ProtocolState() interface{}
	SetProtocolState(state interface{})
	GetData(string) (interface{}, bool)
	SetData(string, interface{})
	DeleteData(string)
	HasData(string) bool
}

// TLSConnectionWrapper used by proxy to wrap raw connections to TLS when intercepts client/database request about switching to TLS
// Reuse network.ConnectionWrapper to explicitly force TLS usage by name
type TLSConnectionWrapper interface {
	WrapDBConnection(ctx context.Context, conn net.Conn) (net.Conn, error)
	WrapClientConnection(ctx context.Context, conn net.Conn) (wrappedConnection net.Conn, clientID []byte, err error)
	UseConnectionClientID() bool
}

type proxyTLSConnectionWrapper struct {
	wrapper               network.ConnectionWrapper
	useConnectionClientID bool
}

// NewTLSConnectionWrapper return wrapper over network.ConnectionWrapper to implement TLSConnectionWrapper interface
func NewTLSConnectionWrapper(useClientID bool, wrapper network.ConnectionWrapper) TLSConnectionWrapper {
	return &proxyTLSConnectionWrapper{wrapper: wrapper, useConnectionClientID: useClientID}
}

func (wrapper *proxyTLSConnectionWrapper) WrapDBConnection(ctx context.Context, conn net.Conn) (net.Conn, error) {
	return wrapper.wrapper.WrapClient(ctx, conn)
}
func (wrapper *proxyTLSConnectionWrapper) WrapClientConnection(ctx context.Context, conn net.Conn) (net.Conn, []byte, error) {
	return wrapper.wrapper.WrapServer(ctx, conn)
}
func (wrapper *proxyTLSConnectionWrapper) UseConnectionClientID() bool {
	return wrapper.useConnectionClientID
}

// ProxyFactory create new Proxy for specific database
type ProxyFactory interface {
	New(clientID []byte, clientSession ClientSession) (Proxy, error)
}

// PreparedStatementRegistry keeps track of active prepared statements and cursors within a ClientSession.
type PreparedStatementRegistry interface {
	AddStatement(statement PreparedStatement) error
	DeleteStatement(name string) error
	StatementByName(name string) (PreparedStatement, error)

	AddCursor(cursor Cursor) error
	DeleteCursor(name string) error
	CursorByName(name string) (Cursor, error)
}

// PreparedStatement is a prepared statement, ready to be executed.
// It can be either a textual SQL statement from "PREPARE", or a database protocol equivalent.
type PreparedStatement interface {
	Name() string
	Query() sqlparser.Statement
	QueryText() string
	ParamsNum() int
}

// Cursor is used to iterate over a prepared statement.
// It can be either a textual SQL statement from "DEFINE CURSOR", or a database protocol equivalent.
type Cursor interface {
	Name() string
	PreparedStatement() PreparedStatement
}

const (
	acraDBProxyErrSide     = "AcraServer-Database"
	acraClientProxyErrSide = "Client/Connector-Database"
)

// ProxyError custom error type for handling all related errors on Client/DB proxies
type ProxyError struct {
	sourceErr     error
	interruptSide string
}

// NewClientProxyError construct ProxyError object with Client interrupt side
func NewClientProxyError(err error) ProxyError {
	return ProxyError{
		sourceErr:     err,
		interruptSide: acraClientProxyErrSide,
	}
}

// NewDBProxyError construct ProxyError object with DB interrupt side
func NewDBProxyError(err error) ProxyError {
	return ProxyError{
		sourceErr:     err,
		interruptSide: acraDBProxyErrSide,
	}
}

func (p ProxyError) Error() string {
	return fmt.Sprintf("%s:%s", p.interruptSide, p.sourceErr.Error())
}

// Unwrap return the source error
func (p ProxyError) Unwrap() error {
	return p.sourceErr
}

// InterruptSide return interruption side where error happened
func (p ProxyError) InterruptSide() string {
	return p.interruptSide
}
