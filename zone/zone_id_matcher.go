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

type KeyChecker interface {
	HasKey([]byte) bool
}

type ZoneIdMatcher struct {
	matched      bool
	matchers     *list.List
	zone_id      []byte
	matcher_pool *MatcherPool
	keychecker   KeyChecker
}

func NewZoneMatcher(matcher_pool *MatcherPool, keychecker KeyChecker) *ZoneIdMatcher {
	matcher := &ZoneIdMatcher{
		matchers:     list.New(),
		matcher_pool: matcher_pool,
		matched:      false,
		keychecker:   keychecker,
	}
	matcher.addEmptyMatcher()
	return matcher
}

func (zone_matcher *ZoneIdMatcher) IsMatched() bool {
	return zone_matcher.matched
}

func (zone_matcher *ZoneIdMatcher) Reset() {
	zone_matcher.matched = false
	zone_matcher.clearMatchers()
}

func (zone_matcher *ZoneIdMatcher) GetZoneId() []byte {
	if zone_matcher.IsMatched() {
		return zone_matcher.zone_id
	} else {
		return []byte{}
	}

}

func (zone_matcher *ZoneIdMatcher) Match(c byte) bool {
	current_element := zone_matcher.matchers.Front()
	var to_remove *list.Element = nil
	var matcher Matcher
	is_matched := false
	for {
		matcher = current_element.Value.(Matcher)
		if matcher.Match(c) {
			if matcher.IsMatched() {
				if zone_matcher.keychecker.HasKey(matcher.GetZoneId()) {
					zone_matcher.zone_id = matcher.GetZoneId()
					zone_matcher.matched = true
					is_matched = true
				}
				to_remove = current_element
			} else {
				is_matched = true
			}
		} else {
			// if no match and it's not last matcher, delete him
			if current_element != zone_matcher.matchers.Back() {
				to_remove = current_element
			}
		}
		// if last matcher (previously was empty) has match, add empty matcher and quit
		if current_element == zone_matcher.matchers.Back() && matcher.HasAnyMatch() {
			zone_matcher.addEmptyMatcher()
			if to_remove != nil {
				zone_matcher.remove(to_remove)
			}
			break
		}

		current_element = current_element.Next()
		if to_remove != nil {
			zone_matcher.remove(to_remove)
			to_remove = nil
		}
		if current_element == nil {
			break
		}
	}
	return is_matched
}

func (zone_matcher *ZoneIdMatcher) remove(element *list.Element) {
	zone_matcher.matchers.Remove(element)
	zone_matcher.matcher_pool.Release(element.Value.(Matcher))
}

func (zone_matcher *ZoneIdMatcher) clearMatchers() {
	/* delete all matcher except the last that should be emptyMatcher */
	var previous *list.Element
	element := zone_matcher.matchers.Front()
	for {
		if element.Next() != nil {
			previous = element
			element = element.Next()
			zone_matcher.remove(previous)
		} else {
			return
		}
	}
}

func (zone_matcher *ZoneIdMatcher) addEmptyMatcher() {
	matcher := zone_matcher.matcher_pool.Acquire()
	zone_matcher.matchers.PushBack(matcher)
}
