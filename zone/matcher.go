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

// should be used ascii symbols as prefix/suffix for using as output and filenames

// were chosen upper symbols because if data is text than it's less possible to
// catch three upper consonants in a row
//var ZONE_ID_BEGIN = []byte{'Z', 'X', 'C'}
//'44' - D - 68 - 0b1000100
var ZONE_TAG_SYMBOL byte = 'D'
var ZONE_ID_BEGIN = []byte{ZONE_TAG_SYMBOL, ZONE_TAG_SYMBOL, ZONE_TAG_SYMBOL, ZONE_TAG_SYMBOL, ZONE_TAG_SYMBOL, ZONE_TAG_SYMBOL, ZONE_TAG_SYMBOL, ZONE_TAG_SYMBOL}

var ZONE_TAG_LENGTH = len(ZONE_ID_BEGIN)
var ZONE_ID_LENGTH = 16
var ZONE_ID_BLOCK_LENGTH = int(ZONE_TAG_LENGTH + ZONE_ID_LENGTH)

type DbByteReader interface {
	ReadByte(c byte) (bool, byte, error)
	GetBuffered() []byte
	Reset()
}

type MatcherFactory interface {
	CreateMatcher() Matcher
}

/* custom matcher factories */

type PgHexMatcherFactory struct{}

func NewPgHexMatcherFactory() MatcherFactory {
	return &PgHexMatcherFactory{}
}

func (*PgHexMatcherFactory) CreateMatcher() Matcher {
	return NewPgMatcher(NewPgHexByteReader())
}

type PgEscapeMatcherFactory struct{}

func NewPgEscapeMatcherFactory() MatcherFactory {
	return &PgEscapeMatcherFactory{}
}

func (*PgEscapeMatcherFactory) CreateMatcher() Matcher {
	return NewPgMatcher(NewPgEscapeByteReader())
}

/* end custom matcher factories */

type Matcher interface {
	Match(byte) bool
	Reset()
	GetZoneId() []byte
	IsMatched() bool
	HasAnyMatch() bool
}

type PgMatcher struct {
	pg_matcher     Matcher
	binary_matcher Matcher
}

func NewPgMatcher(db_reader DbByteReader) Matcher {
	return &PgMatcher{
		pg_matcher:     NewBaseMatcher(db_reader),
		binary_matcher: NewBaseMatcher(NewBinaryByteReader()),
	}
}
func (matcher *PgMatcher) Match(c byte) bool {
	pg_matched := matcher.pg_matcher.Match(c)
	bin_matched := matcher.binary_matcher.Match(c)
	return pg_matched || bin_matched
}

func (matcher *PgMatcher) HasAnyMatch() bool {
	return matcher.pg_matcher.HasAnyMatch() || matcher.binary_matcher.HasAnyMatch()
}

func (matcher *PgMatcher) GetZoneId() []byte {
	if matcher.pg_matcher.IsMatched() {
		return matcher.pg_matcher.GetZoneId()
	} else if matcher.binary_matcher.IsMatched() {
		return matcher.binary_matcher.GetZoneId()
	} else {
		return []byte{}
	}
}
func (matcher *PgMatcher) Reset() {
	matcher.pg_matcher.Reset()
	matcher.binary_matcher.Reset()
}

func (matcher *PgMatcher) IsMatched() bool {
	matched := matcher.pg_matcher.IsMatched()
	matched = matched || matcher.binary_matcher.IsMatched()
	return matched
}

type BaseMatcher struct {
	current_index byte
	matched       bool
	has_any_match bool
	zone_id       []byte
	db_reader     DbByteReader
}

func NewBaseMatcher(db_reader DbByteReader) Matcher {
	return &BaseMatcher{
		current_index: 0,
		db_reader:     db_reader,
		has_any_match: false,
		matched:       false,
		zone_id:       make([]byte, ZONE_ID_BLOCK_LENGTH)}
}

func (matcher *BaseMatcher) Reset() {
	// used only for tests
	matcher.current_index = 0
	matcher.matched = false
	matcher.has_any_match = false
}

func (matcher *BaseMatcher) Match(c byte) bool {
	parsed, b, err := matcher.db_reader.ReadByte(c)
	if err != nil {
		matcher.Reset()
		return false
	}
	// matched part of db byte format
	if !parsed {
		matcher.has_any_match = true
		return true
	}
	matcher.has_any_match = true
	if matcher.current_index < byte(len(ZONE_ID_BEGIN)) {
		if ZONE_ID_BEGIN[matcher.current_index] == b {
			matcher.zone_id[matcher.current_index] = b
			matcher.current_index++
			return true
		} else {
			matcher.Reset()
			return false
		}
	} else {
		matcher.zone_id[matcher.current_index] = b
		matcher.current_index++
		if matcher.current_index == byte(ZONE_ID_BLOCK_LENGTH) {
			matcher.matched = true
		}
		return true
	}
}

func (matcher *BaseMatcher) IsMatched() bool {
	return matcher.matched
}

func (matcher *BaseMatcher) HasAnyMatch() bool {
	return matcher.has_any_match
}

func (matcher *BaseMatcher) GetZoneId() []byte {
	if matcher.IsMatched() {
		return matcher.zone_id
	} else {
		return []byte{}
	}
}
