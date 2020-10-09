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
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/sirupsen/logrus"
)

// OnQueryObject interface for result of OnQuery call
type OnQueryObject interface {
	Statement() (sqlparser.Statement, error)
	Query() string
}

// onQueryObject store result of QueryObserver.OnQuery call to reuse statements/queries between calls and do not parse/encode queries/statements
type onQueryObject struct {
	statement sqlparser.Statement
	query     string
}

// Statement return stored statement or parse query
func (obj *onQueryObject) Statement() (sqlparser.Statement, error) {
	if obj.statement != nil {
		return obj.statement, nil
	}
	return sqlparser.Parse(obj.query)
}

// Query return stored query or encode statement to string
func (obj *onQueryObject) Query() string {
	if obj.query == "" {
		return sqlparser.String(obj.statement)
	}
	return obj.query
}

// NewOnQueryObjectFromStatement return OnQueryObject with Statement as value
func NewOnQueryObjectFromStatement(stmt sqlparser.Statement) OnQueryObject {
	return &onQueryObject{statement: stmt}
}

// NewOnQueryObjectFromQuery return OnQueryObject with query string as value
func NewOnQueryObjectFromQuery(query string) OnQueryObject {
	return &onQueryObject{query: query}
}

// QueryObserver will be used to notify about coming new query
type QueryObserver interface {
	ID() string
	// OnQuery return true if output query was changed otherwise false
	OnQuery(data OnQueryObject) (OnQueryObject, bool, error)
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

// ArrayQueryObserverableManager store all subscribed observes and call sequentially OnQuery on each observer
type ArrayQueryObserverableManager struct {
	subscribers []QueryObserver
	logger      *logrus.Entry
}

// NewArrayQueryObserverableManager create new ArrayQueryObserverableManager
func NewArrayQueryObserverableManager(ctx context.Context) (*ArrayQueryObserverableManager, error) {
	return &ArrayQueryObserverableManager{logger: logging.GetLoggerFromContext(ctx)}, nil
}

// AddQueryObserver observer to array
func (manager *ArrayQueryObserverableManager) AddQueryObserver(obs QueryObserver) {
	manager.subscribers = append(manager.subscribers, obs)
}

// RegisteredObserversCount return count of registered observers
func (manager *ArrayQueryObserverableManager) RegisteredObserversCount() int {
	return len(manager.subscribers)
}

// ID returns name of this QueryObserver.
func (manager *ArrayQueryObserverableManager) ID() string {
	return "ArrayQueryObserverableManager"
}

// OnQuery would be called for each added observer to manager
func (manager *ArrayQueryObserverableManager) OnQuery(query OnQueryObject) (OnQueryObject, bool, error) {
	currentQuery := query
	changedQuery := false
	for _, observer := range manager.subscribers {
		newQuery, changed, err := observer.OnQuery(currentQuery)
		if err != nil {
			manager.logger.WithField("observer", observer.ID()).WithError(err).Errorln("OnQuery failed")
			return query, false, err
		}
		if changed {
			currentQuery = newQuery
			changedQuery = true
		}
	}
	return currentQuery, changedQuery, nil
}
