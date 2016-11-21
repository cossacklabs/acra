package acra

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
