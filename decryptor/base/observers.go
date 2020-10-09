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

// BoundValue is a value provided for prepared statement execution.
// Its exact type and meaning depends on the corresponding query.
type BoundValue interface {
	Data() []byte
	Encoding() BoundValueEncoding
}

// BoundValueEncoding specifies how to interpret the bound data.
type BoundValueEncoding int

// Supported values of BoundValueEncoding.
const (
	BindText BoundValueEncoding = iota
	BindBinary
)

type boundValue struct {
	data     []byte
	encoding BoundValueEncoding
}

// Data of the bound value.
func (v *boundValue) Data() []byte {
	return v.data
}

// Encoding of the bound value data.
func (v *boundValue) Encoding() BoundValueEncoding {
	return v.encoding
}

// NewBoundValue makes a standard BoundValue from value data.
func NewBoundValue(data []byte, encoding BoundValueEncoding) BoundValue {
	return &boundValue{data, encoding}
}

// QueryObserver observes database queries and is able to modify them.
// Methods should return "true" as their second bool result if the data has been modified.
type QueryObserver interface {
	ID() string
	// Simple queries and prepared statements during preparation stage. SQL is modifiable.
	OnQuery(data OnQueryObject) (OnQueryObject, bool, error)
	// Prepared statement parameters during execution stage. Parameter values are modifiable.
	OnBind(statement sqlparser.Statement, values []BoundValue) ([]BoundValue, bool, error)
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

// OnBind would be called for each added observer to manager.
func (manager *ArrayQueryObserverableManager) OnBind(statement sqlparser.Statement, values []BoundValue) ([]BoundValue, bool, error) {
	currentValues := values
	changedValues := false
	for _, observer := range manager.subscribers {
		newValues, changedNow, err := observer.OnBind(statement, currentValues)
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
