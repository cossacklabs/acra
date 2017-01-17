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
package zone_test

import (
	"encoding/hex"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"testing"
)

func assertZoneMatchNotFail(c byte, matcher *zone.ZoneIdMatcher, t *testing.T) {
	if !matcher.Match(c) {
		t.Fatal("Unexpected unmatch")
	}
}

type TestKeyStore struct{}

func (storage *TestKeyStore) GetZonePrivateKey(id []byte) (*keys.PrivateKey, error) {
	return &keys.PrivateKey{Value: []byte{}}, nil
}
func (storage *TestKeyStore) HasZonePrivateKey(id []byte) bool { return true }
func (storage *TestKeyStore) GetProxyPublicKey(id []byte) (*keys.PublicKey, error) {
	return &keys.PublicKey{Value: []byte{}}, nil
}
func (storage *TestKeyStore) GetServerPrivateKey(id []byte) (*keys.PrivateKey, error) {
	return &keys.PrivateKey{Value: []byte{}}, nil
}
func (storage *TestKeyStore) GenerateZoneKey() ([]byte, []byte, error) { return []byte{}, []byte{}, nil }

func (storage *TestKeyStore) Reset()                                     {}
func (storage *TestKeyStore) GenerateProxyKeys(id []byte) error          { return nil }
func (storage *TestKeyStore) GenerateServerKeys(id []byte) error         { return nil }
func (storage *TestKeyStore) GenerateDataEncryptionKeys(id []byte) error { return nil }
func (storage *TestKeyStore) GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error) {
	return nil, nil
}

func testZoneIdMatcher(t *testing.T) {
	var keystorage keystore.KeyStore = &TestKeyStore{}
	matcher_pool := zone.NewMatcherPool(zone.NewPgHexMatcherFactory())
	zone_matcher := zone.NewZoneMatcher(matcher_pool, keystorage)
	var HEX_ZONE_ID_BEGIN = []byte(hex.EncodeToString(zone.ZONE_ID_BEGIN))

	// test correct matching
	t.Log("Check zone id")
	for _, c := range HEX_ZONE_ID_BEGIN {
		assertZoneMatchNotFail(byte(c), zone_matcher, t)
	}
	// fill zone id
	for i := 0; i < (zone.ZONE_ID_LENGTH * 2); i++ {
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
	for i := 0; i < zone.ZONE_ID_LENGTH; i++ {
		assertZoneMatchNotFail('a', zone_matcher, t)
	}

	// feed second correct tag begin in zone_id block
	for _, c := range HEX_ZONE_ID_BEGIN {
		assertZoneMatchNotFail(byte(c), zone_matcher, t)
	}
	// feed correct zone id
	for i := 0; i < (zone.ZONE_ID_LENGTH * 2); i++ {
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
