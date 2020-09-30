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
	"crypto/tls"
	"net"

	acracensor "github.com/cossacklabs/acra/acra-censor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/sqlparser"
)

// ProxySetting provide data access methods for proxy factories
type ProxySetting interface {
	KeyStore() keystore.DecryptionKeyStore
	TableSchemaStore() config.TableSchemaStore
	ClientTLSConfig() *tls.Config
	DatabaseTLSConfig() *tls.Config
	Censor() acracensor.AcraCensorInterface
	DecryptorFactory() DecryptorFactory
}

type proxySetting struct {
	keystore         keystore.DecryptionKeyStore
	tableSchemaStore config.TableSchemaStore
	clientTLSConfig  *tls.Config
	dbTLSConfig      *tls.Config
	censor           acracensor.AcraCensorInterface
	decryptorFactory DecryptorFactory
}

// DecryptorFactory return configure DecryptorFactory
func (p *proxySetting) DecryptorFactory() DecryptorFactory {
	return p.decryptorFactory
}

// Censor return AcraCensorInterface implementation
func (p *proxySetting) Censor() acracensor.AcraCensorInterface {
	return p.censor
}

// ClientTLSConfig return tls.Config to use when accepting connections from AcraConnectors.
func (p *proxySetting) ClientTLSConfig() *tls.Config {
	return p.clientTLSConfig
}

// DatabaseTLSConfig return tls.Config to use when connecting to the database.
func (p *proxySetting) DatabaseTLSConfig() *tls.Config {
	return p.dbTLSConfig
}

// TableSchemaStore return table schema store
func (p *proxySetting) TableSchemaStore() config.TableSchemaStore {
	return p.tableSchemaStore
}

// KeyStore return keystore
func (p *proxySetting) KeyStore() keystore.DecryptionKeyStore {
	return p.keystore
}

// NewProxySetting return new ProxySetting implementation with data from params
func NewProxySetting(decryptorFactory DecryptorFactory, tableSchema config.TableSchemaStore, keystore keystore.DecryptionKeyStore, clientTLSConfig, dbTLSConfig *tls.Config, censor acracensor.AcraCensorInterface) ProxySetting {
	return &proxySetting{keystore: keystore, tableSchemaStore: tableSchema, clientTLSConfig: clientTLSConfig, dbTLSConfig: dbTLSConfig, censor: censor, decryptorFactory: decryptorFactory}
}

// Proxy interface to process client's requests to database and responses
type Proxy interface {
	QueryObservable
	ProxyClientConnection(chan<- error)
	ProxyDatabaseConnection(chan<- error)
}

// ClientSession is a connection between the client and the database, mediated by AcraServer.
type ClientSession interface {
	Context() context.Context
	ClientConnection() net.Conn
	DatabaseConnection() net.Conn

	PreparedStatementRegistry() PreparedStatementRegistry
	SetPreparedStatementRegistry(registry PreparedStatementRegistry)
}

// ProxyFactory create new Proxy for specific database
type ProxyFactory interface {
	New(clientID []byte, clientSession ClientSession) (Proxy, error)
}

// PreparedStatementRegistry keeps track of active prepared statements within a ClientSession.
type PreparedStatementRegistry interface {
	Add(statement PreparedStatement) (bool, error)
	StatementByName(name string) (PreparedStatement, error)
}

// PreparedStatement is a prepared statement, ready to be executed.
// It can be either a textual SQL statement from "PREPARE", or a database protocol equivalent.
type PreparedStatement interface {
	Name() string
	Query() sqlparser.Statement
	QueryText() string
}
