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
	pgMatcher     Matcher
	binaryMatcher Matcher
}

func NewPgMatcher(dbReader DbByteReader) Matcher {
	return &PgMatcher{
		pgMatcher:     NewBaseMatcher(dbReader),
		binaryMatcher: NewBaseMatcher(NewBinaryByteReader()),
	}
}
func (matcher *PgMatcher) Match(c byte) bool {
	pgMatched := matcher.pgMatcher.Match(c)
	binMatched := matcher.binaryMatcher.Match(c)
	return pgMatched || binMatched
}

func (matcher *PgMatcher) HasAnyMatch() bool {
	return matcher.pgMatcher.HasAnyMatch() || matcher.binaryMatcher.HasAnyMatch()
}

func (matcher *PgMatcher) GetZoneId() []byte {
	if matcher.pgMatcher.IsMatched() {
		return matcher.pgMatcher.GetZoneId()
	} else if matcher.binaryMatcher.IsMatched() {
		return matcher.binaryMatcher.GetZoneId()
	} else {
		return []byte{}
	}
}
func (matcher *PgMatcher) Reset() {
	matcher.pgMatcher.Reset()
	matcher.binaryMatcher.Reset()
}

func (matcher *PgMatcher) IsMatched() bool {
	matched := matcher.pgMatcher.IsMatched()
	matched = matched || matcher.binaryMatcher.IsMatched()
	return matched
}

type BaseMatcher struct {
	currentIndex byte
	matched      bool
	hasAnyMatch  bool
	zoneId       []byte
	dbReader     DbByteReader
}

func NewBaseMatcher(dbReader DbByteReader) Matcher {
	return &BaseMatcher{
		currentIndex: 0,
		dbReader:     dbReader,
		hasAnyMatch:  false,
		matched:      false,
		zoneId:       make([]byte, ZONE_ID_BLOCK_LENGTH)}
}

func (matcher *BaseMatcher) Reset() {
	// used only for tests
	matcher.currentIndex = 0
	matcher.matched = false
	matcher.hasAnyMatch = false
}

func (matcher *BaseMatcher) Match(c byte) bool {
	parsed, b, err := matcher.dbReader.ReadByte(c)
	if err != nil {
		matcher.Reset()
		return false
	}
	// matched part of db byte format
	if !parsed {
		matcher.hasAnyMatch = true
		return true
	}
	matcher.hasAnyMatch = true
	if matcher.currentIndex < byte(len(ZONE_ID_BEGIN)) {
		if ZONE_ID_BEGIN[matcher.currentIndex] == b {
			matcher.zoneId[matcher.currentIndex] = b
			matcher.currentIndex++
			return true
		}
		matcher.Reset()
		return false
	} else {
		matcher.zoneId[matcher.currentIndex] = b
		matcher.currentIndex++
		if matcher.currentIndex == byte(ZONE_ID_BLOCK_LENGTH) {
			matcher.matched = true
		}
		return true
	}
}

func (matcher *BaseMatcher) IsMatched() bool {
	return matcher.matched
}

func (matcher *BaseMatcher) HasAnyMatch() bool {
	return matcher.hasAnyMatch
}

func (matcher *BaseMatcher) GetZoneId() []byte {
	if matcher.IsMatched() {
		return matcher.zoneId
	}
	return []byte{}
}
