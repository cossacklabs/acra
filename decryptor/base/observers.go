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

// QueryObserver will be used to notify about coming new query
type QueryObserver interface {
	// OnQuery return true if output query was changed otherwise false
	OnQuery(query string) (string, bool, error)
}

// QueryObservable used to handle subscribers for new incoming queries
type QueryObservable interface {
	AddQueryObserver(QueryObserver)
}

type QueryObserverManager interface {
	QueryObserver
	QueryObservable
}

// ArrayQueryObserverableManager store all subscribed observes and call sequentially OnQuery on each observer
type ArrayQueryObserverableManager struct {
	subscribers []QueryObserver
}

// Add observer to array
func (manager *ArrayQueryObserverableManager) AddQueryObserver(obs QueryObserver) {
	manager.subscribers = append(manager.subscribers, obs)
}

// OnQuery would be called for each added observer to manager
func (manager *ArrayQueryObserverableManager) OnQuery(query string) (string, bool, error) {
	changedOut := false
	for _, obs := range manager.subscribers {
		newQuery, changed, err := obs.OnQuery(query)
		if err != nil {
			return query, false, err
		}
		if changed {
			changedOut = changed
			query = newQuery
		}
	}
	return query, changedOut, nil
}
