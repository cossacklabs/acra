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

package common

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	log "github.com/sirupsen/logrus"
)

// ClientSession handles connection between database and AcraServer.
type ClientSession struct {
	config         *Config
	connection     net.Conn
	connectionToDb net.Conn
	ctx            context.Context
	logger         *log.Entry
	statements     base.PreparedStatementRegistry
	protocolState  interface{}
	data           map[string]interface{}
}

var sessionCounter uint32

// NewClientSession creates new ClientSession object.
func NewClientSession(ctx context.Context, config *Config, connection net.Conn) (*ClientSession, error) {
	// Give each client session a unique ID (within an AcraServer instance).
	// This greatly simplifies tracking session activity across the logs.
	sessionID := atomic.AddUint32(&sessionCounter, 1)
	logger := logging.GetLoggerFromContext(ctx)
	logger = logger.WithField("session_id", sessionID)
	session := &ClientSession{connection: connection, config: config, ctx: ctx, logger: logger,
		data: make(map[string]interface{}, 8)}
	ctx = logging.SetLoggerToContext(ctx, logger)
	ctx = base.SetClientSessionToContext(ctx, session)
	session.ctx = ctx
	return session, nil

}

// SetData save session related data by key
func (clientSession *ClientSession) SetData(key string, data interface{}) {
	clientSession.data[key] = data
}

// GetData return session related data by key and true otherwise nil, false
func (clientSession *ClientSession) GetData(key string) (interface{}, bool) {
	value, ok := clientSession.data[key]
	return value, ok
}

// DeleteData delete session related data by key
func (clientSession *ClientSession) DeleteData(key string) {
	delete(clientSession.data, key)
}

// HasData return true if session has data by key
func (clientSession *ClientSession) HasData(key string) bool {
	_, ok := clientSession.data[key]
	return ok
}

// Logger returns session's logger.
func (clientSession *ClientSession) Logger() *log.Entry {
	return clientSession.logger
}

// Context returns session's context.
func (clientSession *ClientSession) Context() context.Context {
	return clientSession.ctx
}

// ClientConnection returns connection to AcraConnector.
func (clientSession *ClientSession) ClientConnection() net.Conn {
	return clientSession.connection
}

// DatabaseConnection returns connection to database.
// It must be established first by ConnectToDb().
func (clientSession *ClientSession) DatabaseConnection() net.Conn {
	return clientSession.connectionToDb
}

// PreparedStatementRegistry returns prepared statement registry of this session.
// The session does not have a registry by default, it must be set with SetPreparedStatementRegistry.
func (clientSession *ClientSession) PreparedStatementRegistry() base.PreparedStatementRegistry {
	return clientSession.statements
}

// SetPreparedStatementRegistry sets prepared statement registry for this session.
func (clientSession *ClientSession) SetPreparedStatementRegistry(registry base.PreparedStatementRegistry) {
	clientSession.statements = registry
}

// ProtocolState returns private protocol state of this session.
// The session does not have any state by default, it must be set with SetProtocolState.
func (clientSession *ClientSession) ProtocolState() interface{} {
	return clientSession.protocolState
}

// SetProtocolState sets protocol state for this session.
func (clientSession *ClientSession) SetProtocolState(state interface{}) {
	clientSession.protocolState = state
}

// ConnectToDb connects to the database via tcp using Host and Port from config.
func (clientSession *ClientSession) ConnectToDb() error {
	conn, err := network.Dial(network.BuildConnectionString("tcp", clientSession.config.GetDBHost(), clientSession.config.GetDBPort(), ""))
	if err != nil {
		return err
	}
	clientSession.connectionToDb = conn
	return nil
}

// Close session connections to AcraConnector and database.
func (clientSession *ClientSession) Close() {
	clientSession.logger.Debugln("Close acra-connector connection")

	err := clientSession.connection.Close()
	if err != nil {
		clientSession.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnectionToService).
			Errorln("Error with closing connection to acra-connector")
	}
	clientSession.logger.Debugln("Close db connection")
	err = clientSession.connectionToDb.Close()
	if err != nil {
		clientSession.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnectionDB).
			Errorln("Error with closing connection to db")
	}
	clientSession.logger.Debugln("All connections closed")
}