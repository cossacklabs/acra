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

package handlers

// QueryIgnoreHandler allows to ignore any query
type QueryIgnoreHandler struct {
	ignoredQueries map[string]bool
}

// NewQueryIgnoreHandler creates new ignore handler
func NewQueryIgnoreHandler() *QueryIgnoreHandler {
	handler := &QueryIgnoreHandler{}
	handler.ignoredQueries = make(map[string]bool)
	return handler
}

// CheckQuery checks each query, returns false if query handling should be ignored.
func (handler *QueryIgnoreHandler) CheckQuery(query string) (bool, error) {
	if handler.ignoredQueries[query] {
		//do not continue query handling
		return false, nil
	}
	return true, nil
}

// Reset ignored patterns
func (handler *QueryIgnoreHandler) Reset() {
	handler.ignoredQueries = make(map[string]bool)
}

// Release / reset ignored patterns
func (handler *QueryIgnoreHandler) Release() {
	handler.Reset()
}

// AddQueries normalizes and adds queries to the list that should be ignored
func (handler *QueryIgnoreHandler) AddQueries(queries []string) {
	for _, query := range queries {
		normalizedQuery, _, err := NormalizeAndRedactSQLQuery(query)
		if err != nil {
			continue
		}
		handler.ignoredQueries[normalizedQuery] = true
	}
}

// RemoveQueries removes queries from the list that should be whitelisted
func (handler *QueryIgnoreHandler) RemoveQueries(queries []string) {
	for _, query := range queries {
		normalizedQuery, _, err := NormalizeAndRedactSQLQuery(query)
		if err != nil {
			continue
		}
		delete(handler.ignoredQueries, normalizedQuery)
	}
}
