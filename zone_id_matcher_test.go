package acra_test

import (
	"github.com/cossacklabs/acra"
	"encoding/hex"
	"github.com/cossacklabs/themis/gothemis/keys"
	"testing"
)

func assertZoneMatchNotFail(c byte, matcher *acra.ZoneIdMatcher, t *testing.T) {
	if !matcher.Match(c) {
		t.Fatal("Unexpected unmatch")
	}
}

func testZoneIdMatcher(t *testing.T) {
	var keystore acra.KeyStore = acra.NewOneKeyStore(&keys.PrivateKey{Value: []byte("aaaaaaaaaaaaaaa")})
	matcher_pool := acra.NewMatcherPool(acra.NewPgHexMatcherFactory())
	zone_matcher := acra.NewZoneMatcher(matcher_pool, keystore)
	var HEX_ZONE_ID_BEGIN = []byte(hex.EncodeToString(acra.ZONE_ID_BEGIN))

	// test correct matching
	t.Log("Check zone id")
	for _, c := range HEX_ZONE_ID_BEGIN {
		assertZoneMatchNotFail(byte(c), zone_matcher, t)
	}
	// fill zone id
	for i := 0; i < (acra.ZONE_ID_LENGTH * 2); i++ {
		assertZoneMatchNotFail('a', zone_matcher, t)
	}

	if !zone_matcher.IsMatched() {
		t.Fatal("Expected matched status")
		return
	}
	zone_matcher.Reset()

	// test correct matching inner zone id
	t.Log("Check inner zone id")
	// feed correct tag begin
	for _, c := range HEX_ZONE_ID_BEGIN {
		assertZoneMatchNotFail(byte(c), zone_matcher, t)
	}
	// feed half of correct zone id
	for i := 0; i < acra.ZONE_ID_LENGTH; i++ {
		assertZoneMatchNotFail('a', zone_matcher, t)
	}

	// feed second correct tag begin in zone_id block
	for _, c := range HEX_ZONE_ID_BEGIN {
		assertZoneMatchNotFail(byte(c), zone_matcher, t)
	}
	// feed correct zone id
	for i := 0; i < (acra.ZONE_ID_LENGTH * 2); i++ {
		assertZoneMatchNotFail('a', zone_matcher, t)
	}

	if !zone_matcher.IsMatched() {
		t.Fatal("Expected matched status")
		return
	}
}

func TestZoneIdMatcher(t *testing.T) {
	testZoneIdMatcher(t)
}
