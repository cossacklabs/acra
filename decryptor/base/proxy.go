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
	tlsConfig        *tls.Config
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

// ClientTLSConfig return tls.Config to use for database connection, if any.
func (p *proxySetting) ClientTLSConfig() *tls.Config {
	return p.tlsConfig
}

// DatabaseTLSConfig return tls.Config to use for database connection, if any.
func (p *proxySetting) DatabaseTLSConfig() *tls.Config {
	return p.tlsConfig
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
func NewProxySetting(decryptorFactory DecryptorFactory, tableSchema config.TableSchemaStore, keystore keystore.DecryptionKeyStore, tlsConfig *tls.Config, censor acracensor.AcraCensorInterface) ProxySetting {
	return &proxySetting{keystore: keystore, tableSchemaStore: tableSchema, tlsConfig: tlsConfig, censor: censor, decryptorFactory: decryptorFactory}
}

// Proxy interface to process client's requests to database and responses
type Proxy interface {
	QueryObservable
	ProxyClientConnection(chan<- error)
	ProxyDatabaseConnection(chan<- error)
}

// ProxyFactory create new Proxy for specific database
type ProxyFactory interface {
	New(ctx context.Context, clientID []byte, dbConnection, clientConnection net.Conn) (Proxy, error)
}
