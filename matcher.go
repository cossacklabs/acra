package acra

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
		if matcher.current_index == ZONE_ID_BLOCK_LENGTH {
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
