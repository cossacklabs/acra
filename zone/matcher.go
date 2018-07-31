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

// should be used ascii symbols as prefix/suffix for using as output and filenames

// were chosen upper symbols because if data is text than it's less possible to
// catch three upper consonants in a row
//var ZONE_ID_BEGIN = []byte{'Z', 'X', 'C'}
//'44' - D - 68 - 0b1000100
var (
	ZONE_TAG_SYMBOL      byte = 'D'
	ZONE_ID_BEGIN             = []byte{ZONE_TAG_SYMBOL, ZONE_TAG_SYMBOL, ZONE_TAG_SYMBOL, ZONE_TAG_SYMBOL, ZONE_TAG_SYMBOL, ZONE_TAG_SYMBOL, ZONE_TAG_SYMBOL, ZONE_TAG_SYMBOL}
	ZONE_TAG_LENGTH           = len(ZONE_ID_BEGIN)
	ZONE_ID_LENGTH            = 16
	ZONE_ID_BLOCK_LENGTH      = int(ZONE_TAG_LENGTH + ZONE_ID_LENGTH)
)

// DbByteReader reads bytes
type DbByteReader interface {
	ReadByte(c byte) (bool, byte, error)
	GetBuffered() []byte
	Reset()
}

// MatcherFactory creates matchers
type MatcherFactory interface {
	CreateMatcher() Matcher
}

/* custom matcher factories */

// PgHexMatcherFactory makes new pgMatchers for HexBytes mode
type PgHexMatcherFactory struct{}

// NewPgHexMatcherFactory creates new PgHexMatcherFactory
func NewPgHexMatcherFactory() MatcherFactory {
	return &PgHexMatcherFactory{}
}

// CreateMatcher returns new PgHexMatcher
func (*PgHexMatcherFactory) CreateMatcher() Matcher {
	return NewPgMatcher(NewPgHexByteReader())
}

// PgEscapeMatcherFactory makes new pgMatchers for EscapedBytes mode
type PgEscapeMatcherFactory struct{}

// NewPgEscapeMatcherFactory creates new PgEscapeMatcherFactory
func NewPgEscapeMatcherFactory() MatcherFactory {
	return &PgEscapeMatcherFactory{}
}

// CreateMatcher returns new PgEscapeMatcher
func (*PgEscapeMatcherFactory) CreateMatcher() Matcher {
	return NewPgMatcher(NewPgEscapeByteReader())
}

/* end custom matcher factories */

// Matcher basic interface
type Matcher interface {
	Match(byte) bool
	Reset()
	GetZoneID() []byte
	IsMatched() bool
	HasAnyMatch() bool
}

// PgMatcher concatenates two matchers: pgMatcher and binaryMatcher
type PgMatcher struct {
	pgMatcher     Matcher
	binaryMatcher Matcher
}

// NewPgMatcher returns new Matcher with pgMatcher and binaryMatcher
func NewPgMatcher(dbReader DbByteReader) Matcher {
	return &PgMatcher{
		pgMatcher:     NewBaseMatcher(dbReader),
		binaryMatcher: NewBaseMatcher(NewBinaryByteReader()),
	}
}

// Match returns true if pgMatcher or binaryMatcher has ZONE_ID block inside c bytes
func (matcher *PgMatcher) Match(c byte) bool {
	pgMatched := matcher.pgMatcher.Match(c)
	binMatched := matcher.binaryMatcher.Match(c)
	return pgMatched || binMatched
}

// HasAnyMatch returns true if pgMatcher or binaryMatcher has any match
func (matcher *PgMatcher) HasAnyMatch() bool {
	return matcher.pgMatcher.HasAnyMatch() || matcher.binaryMatcher.HasAnyMatch()
}

// GetZoneID returns true if pgMatcher or binaryMatcher has zoneID
// return empty bytes if no zoneID found
func (matcher *PgMatcher) GetZoneID() []byte {
	if matcher.pgMatcher.IsMatched() {
		return matcher.pgMatcher.GetZoneID()
	} else if matcher.binaryMatcher.IsMatched() {
		return matcher.binaryMatcher.GetZoneID()
	} else {
		return []byte{}
	}
}

// Reset both pgMatcher and binaryMatcher
func (matcher *PgMatcher) Reset() {
	matcher.pgMatcher.Reset()
	matcher.binaryMatcher.Reset()
}

// IsMatched returns true if pgMatcher or binaryMatcher has match
func (matcher *PgMatcher) IsMatched() bool {
	matched := matcher.pgMatcher.IsMatched()
	matched = matched || matcher.binaryMatcher.IsMatched()
	return matched
}

// BaseMatcher looks for zoneID in bytes read by dbReader
type BaseMatcher struct {
	currentIndex byte
	matched      bool
	hasAnyMatch  bool
	zoneID       []byte
	dbReader     DbByteReader
}

// NewBaseMatcher returns new Matcher
func NewBaseMatcher(dbReader DbByteReader) Matcher {
	return &BaseMatcher{
		currentIndex: 0,
		dbReader:     dbReader,
		hasAnyMatch:  false,
		matched:      false,
		zoneID:       make([]byte, ZONE_ID_BLOCK_LENGTH)}
}

// Reset changes Matcher state to the initial one, used in tests only
func (matcher *BaseMatcher) Reset() {
	// used only for tests
	matcher.currentIndex = 0
	matcher.matched = false
	matcher.hasAnyMatch = false
}

// Match returns true if c has ZONE_ID block
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
			matcher.zoneID[matcher.currentIndex] = b
			matcher.currentIndex++
			return true
		}
		matcher.Reset()
		return false
	}
	matcher.zoneID[matcher.currentIndex] = b
	matcher.currentIndex++
	if matcher.currentIndex == byte(ZONE_ID_BLOCK_LENGTH) {
		matcher.matched = true
	}
	return true
}

// IsMatched true if matched
func (matcher *BaseMatcher) IsMatched() bool {
	return matcher.matched
}

// HasAnyMatch true if has any match
func (matcher *BaseMatcher) HasAnyMatch() bool {
	return matcher.hasAnyMatch
}

// GetZoneID returns zoneID or empty bytes
func (matcher *BaseMatcher) GetZoneID() []byte {
	if matcher.IsMatched() {
		return matcher.zoneID
	}
	return []byte{}
}
