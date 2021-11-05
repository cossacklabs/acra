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

// Package zone contains AcraStruct's zone matchers and readers.
// Zones are the way to cryptographically compartmentalise records in an already-encrypted environment.
// Zones rely on different private keys on the server side.
// Acra uses ZoneID identifier to identify, which key to use for decryption of a corresponding AcraStruct.
//
// The idea behind Zones is very simple: when we store sensitive data, it's frequently related
// to users / companies / some other binding entities. These entities could be described through
// some real-world identifiers, or (preferably) random identifiers, which have no computable relationship
// to the protected data.
//
// https://github.com/cossacklabs/acra/wiki/Zones
package zone

import (
	"bytes"
	"crypto/rand"
	"testing"
)

type TestKeyStore struct{ ZoneID []byte }

func (storage *TestKeyStore) HasZonePrivateKey(id []byte) bool {
	return bytes.Equal(id, storage.ZoneID)
}

func testZoneIDMatcher(t *testing.T) {
	testZoneID := GenerateZoneID()
	keychecker := &TestKeyStore{ZoneID: testZoneID}
	zoneMatcher := NewZoneMatcher(keychecker)

	if zoneMatcher.Match(ZoneIDBegin) {
		t.Fatal("Unexpected match of begin tag only")
	}
	if zoneMatcher.IsMatched() {
		t.Fatal("Invalid matched flag")
	}
	if zoneMatcher.GetZoneID() != nil {
		t.Fatal("Returns invalid ZoneID")
	}
	fakeZone := make([]byte, 0, ZoneIDLength)
	fakeZone = append(fakeZone, ZoneIDBegin...)
	rand.Read(fakeZone)
	if zoneMatcher.Match(fakeZone) {
		t.Fatal("Unexpected match of fake ZoneID with correct begin tag")
	}
	if zoneMatcher.IsMatched() {
		t.Fatal("Invalid matched flag")
	}
	if zoneMatcher.GetZoneID() != nil {
		t.Fatal("Returns invalid ZoneID")
	}

	// test correct match
	if !zoneMatcher.Match(testZoneID) {
		t.Fatal("Not matched correct ZoneID")
	}
	if !zoneMatcher.IsMatched() {
		t.Fatal("Return false for IsMatched after correct ZoneID")
	}
	if !bytes.Equal(zoneMatcher.GetZoneID(), testZoneID) {
		t.Fatal("Returns invalid ZoneID")
	}

	zoneMatcher.Reset()
	if zoneMatcher.GetZoneID() != nil {
		t.Fatal("Returns invalid ZoneID")
	}
	if zoneMatcher.IsMatched() {
		t.Fatal("Return true for IsMatched after Reset")
	}

}

func TestZoneIDMatcher(t *testing.T) {
	testZoneIDMatcher(t)
}
