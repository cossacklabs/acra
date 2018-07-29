// Package zone contains AcraStruct's zone matchers and readers.
//
// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package zone

import (
	"container/list"
)

type MatcherPool struct {
	factory  MatcherFactory
	matchers *list.List
}

func NewMatcherPool(factory MatcherFactory) *MatcherPool {
	return &MatcherPool{factory: factory, matchers: list.New()}
}

func (pool *MatcherPool) Acquire() Matcher {
	if pool.matchers.Len() == 0 {
		return pool.factory.CreateMatcher()
	}
	/*pop from matchers and return*/
	matcher := pool.matchers.Remove(pool.matchers.Front())
	return matcher.(Matcher)
}
func (pool *MatcherPool) Release(matcher Matcher) {
	matcher.Reset()
	pool.matchers.PushFront(matcher)
}
