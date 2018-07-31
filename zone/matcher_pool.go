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

// Package zone contains AcraStruct's zone matchers and readers.
// Zones are the way to cryptographically compartmentalise records in an already-encrypted environment.
// Zones rely on different private keys on the server side.
// Acra uses ZoneID identifier to identify, which key to use for decryption of a corresponding AcraStruct.
//
// The idea behind Zones is very simple: when we store sensitive data, it's frequently related
// to users / companies / some other binding entities. These entities could be described through
// some real-world identifiers, or (preferably) random identifiers, which have no computable relationship
// to the protected data.
//
// https://github.com/cossacklabs/acra/wiki/Zones
package zone

import (
	"container/list"
)

// MatcherPool stores MatcherFactory and list of matchers
type MatcherPool struct {
	factory  MatcherFactory
	matchers *list.List
}

// NewMatcherPool returns new MatcherPool with empty list of matchers
func NewMatcherPool(factory MatcherFactory) *MatcherPool {
	return &MatcherPool{factory: factory, matchers: list.New()}
}

// Acquire returns first matcher from the list, or creates one from factory if matchers list is empty
func (pool *MatcherPool) Acquire() Matcher {
	if pool.matchers.Len() == 0 {
		return pool.factory.CreateMatcher()
	}
	/*pop from matchers and return*/
	matcher := pool.matchers.Remove(pool.matchers.Front())
	return matcher.(Matcher)
}

// Release resets matcher and push it to the start of the list
func (pool *MatcherPool) Release(matcher Matcher) {
	matcher.Reset()
	pool.matchers.PushFront(matcher)
}
