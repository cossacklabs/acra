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

package mysql

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
)

// OnQueryObject interface for result of OnQuery call
type OnQueryObject interface {
	Statement() (sqlparser.Statement, error)
	Query() string
}

// onQueryObject store result of QueryObserver.OnQuery call to reuse statements/queries between calls and do not parse/encode queries/statements
type onQueryObject struct {
	statement sqlparser.Statement
	parser    *sqlparser.Parser
	query     string
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

// QueryObserver observes database queries and is able to modify them.
// Methods should return "true" as their second bool result if the data has been modified.
type QueryObserver interface {
	ID() string
	// Simple queries and prepared statements during preparation stage. SQL is modifiable.
	OnQuery(ctx context.Context, data OnQueryObject) (OnQueryObject, bool, error)
	// Prepared statement parameters during execution stage. Parameter values are modifiable.
	OnBind(ctx context.Context, statement sqlparser.Statement, values []base.BoundValue) ([]base.BoundValue, bool, error)
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
func (manager *ArrayQueryObservableManager) OnBind(ctx context.Context, statement sqlparser.Statement, values []base.BoundValue) ([]base.BoundValue, bool, error) {
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
