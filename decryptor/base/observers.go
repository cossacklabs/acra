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

	pg_query "github.com/Zhaars/pg_query_go/v4"
	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
)

// OnQueryObject interface for result of OnQuery call
type OnQueryObject interface {
	Statement() (sqlparser.Statement, error)
	// PgStatement temporal method not to break the interface
	PgStatement() (*pg_query.ParseResult, error)
	Query() string
}

// onQueryObject store result of QueryObserver.OnQuery call to reuse statements/queries between calls and do not parse/encode queries/statements
type onQueryObject struct {
	statement   sqlparser.Statement
	pgStatement *pg_query.ParseResult
	parser      *sqlparser.Parser
	query       string
}

func (obj *onQueryObject) PgStatement() (*pg_query.ParseResult, error) {
	if obj.pgStatement != nil {
		return obj.pgStatement, nil
	}
	return pg_query.Parse(obj.query)
}

// Statement return stored statement or parse query
func (obj *onQueryObject) Statement() (sqlparser.Statement, error) {
	if obj.statement != nil {
		return obj.statement, nil
	}
	return obj.parser.Parse(obj.query)
}

// Query return stored query or encode statement to string
func (obj *onQueryObject) Query() string {
	if obj.query == "" {
		return sqlparser.String(obj.statement)
	}
	return obj.query
}

// NewOnQueryObjectFromStatement return OnQueryObject with Statement as value
func NewOnQueryObjectFromStatement(stmt sqlparser.Statement, parser *sqlparser.Parser) OnQueryObject {
	return &onQueryObject{statement: stmt, parser: parser}
}

// NewOnQueryObjectFromQuery return OnQueryObject with query string as value
func NewOnQueryObjectFromQuery(query string, parser *sqlparser.Parser) OnQueryObject {
	return &onQueryObject{query: query, parser: parser}
}

// BoundValue is a value provided for prepared statement execution.
// Its exact type and meaning depends on the corresponding query.
type BoundValue interface {
	Format() BoundValueFormat
	Copy() BoundValue
	SetData(newData []byte, setting config.ColumnEncryptionSetting) error
	GetData(setting config.ColumnEncryptionSetting) ([]byte, error)
	Encode() ([]byte, error)
	GetType() byte
}

// BoundValueFormat specifies how to interpret the bound data.
type BoundValueFormat uint16

// Supported values of BoundValueFormat.
const (
	TextFormat BoundValueFormat = iota
	BinaryFormat
)

// QueryObserver observes database queries and is able to modify them.
// Methods should return "true" as their second bool result if the data has been modified.
type QueryObserver interface {
	ID() string
	// Simple queries and prepared statements during preparation stage. SQL is modifiable.
	OnQuery(ctx context.Context, data OnQueryObject) (OnQueryObject, bool, error)
	// Prepared statement parameters during execution stage. Parameter values are modifiable.
	OnBind(ctx context.Context, statement sqlparser.Statement, values []BoundValue) ([]BoundValue, bool, error)
}

// QueryObservable used to handle subscribers for new incoming queries
type QueryObservable interface {
	AddQueryObserver(QueryObserver)
	RegisteredObserversCount() int
}

// QueryObserverManager interface for observer aggregations
type QueryObserverManager interface {
	QueryObserver
	QueryObservable
}

// ArrayQueryObservableManager store all subscribed observes and call sequentially OnQuery on each observer
type ArrayQueryObservableManager struct {
	subscribers []QueryObserver
	logger      *logrus.Entry
}

// NewArrayQueryObservableManager create new ArrayQueryObservableManager
func NewArrayQueryObservableManager(ctx context.Context) (*ArrayQueryObservableManager, error) {
	return &ArrayQueryObservableManager{logger: logging.GetLoggerFromContext(ctx)}, nil
}

// AddQueryObserver observer to array
func (manager *ArrayQueryObservableManager) AddQueryObserver(obs QueryObserver) {
	manager.subscribers = append(manager.subscribers, obs)
}

// RegisteredObserversCount return count of registered observers
func (manager *ArrayQueryObservableManager) RegisteredObserversCount() int {
	return len(manager.subscribers)
}

// ID returns name of this QueryObserver.
func (manager *ArrayQueryObservableManager) ID() string {
	return "ArrayQueryObservableManager"
}

// OnQuery would be called for each added observer to manager
func (manager *ArrayQueryObservableManager) OnQuery(ctx context.Context, query OnQueryObject) (OnQueryObject, bool, error) {
	currentQuery := query
	changedQuery := false
	for _, observer := range manager.subscribers {
		newQuery, changed, err := observer.OnQuery(ctx, currentQuery)
		if err != nil {
			manager.logger.WithField("observer", observer.ID()).WithError(err).Debugln("OnQuery failed")
			return query, false, err
		}
		if changed {
			currentQuery = newQuery
			changedQuery = true
		}
	}
	return currentQuery, changedQuery, nil
}

// OnBind would be called for each added observer to manager.
func (manager *ArrayQueryObservableManager) OnBind(ctx context.Context, statement sqlparser.Statement, values []BoundValue) ([]BoundValue, bool, error) {
	currentValues := values
	changedValues := false
	for _, observer := range manager.subscribers {
		newValues, changedNow, err := observer.OnBind(ctx, statement, currentValues)
		if err != nil {
			return values, false, err
		}
		if changedNow {
			currentValues = newValues
			changedValues = true
		}
	}
	return currentValues, changedValues, nil
}

// ClientIDObserver used to notify subscribers about changed ClientID in encryption/decryption context
type ClientIDObserver interface {
	OnNewClientID(clientID []byte)
}

// ClientIDObservable used to subscribe for clientID changes
type ClientIDObservable interface {
	AddClientIDObserver(ClientIDObserver)
}

// ClientIDObservableManager used to subscribe for clientID changes and notify about changes
type ClientIDObservableManager interface {
	ClientIDObservable
	ClientIDObserver
}

// ArrayClientIDObservableManager store all subscribed observes and call sequentially OnQuery on each observer
type ArrayClientIDObservableManager struct {
	subscribers []ClientIDObserver
	logger      *logrus.Entry
}

// NewArrayClientIDObservableManager create new ArrayClientIDObservableManager
func NewArrayClientIDObservableManager(ctx context.Context) (*ArrayClientIDObservableManager, error) {
	return &ArrayClientIDObservableManager{logger: logging.GetLoggerFromContext(ctx)}, nil
}

// AddClientIDObserver add new subscriber for clientID changes
func (manager *ArrayClientIDObservableManager) AddClientIDObserver(observer ClientIDObserver) {
	manager.subscribers = append(manager.subscribers, observer)
}

// OnNewClientID pass clientID to subscribers
func (manager *ArrayClientIDObservableManager) OnNewClientID(clientID []byte) {
	for _, subscriber := range manager.subscribers {
		subscriber.OnNewClientID(clientID)
	}
}
