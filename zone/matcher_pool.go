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

// acquire returns first matcher from the list, or creates one from factory if matchers list is empty
func (pool *MatcherPool) acquire() matcher {
	if pool.matchers.Len() == 0 {
		return pool.factory.createMatcher()
	}
	/*pop from matchers and return*/
	matcherImpl := pool.matchers.Remove(pool.matchers.Front())
	return matcherImpl.(matcher)
}

// release resets matcher and push it to the start of the list
func (pool *MatcherPool) release(matcher matcher) {
	matcher.Reset()
	pool.matchers.PushFront(matcher)
}
