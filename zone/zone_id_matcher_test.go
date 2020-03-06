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
package zone_test

import (
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"testing"
)

func assertZoneMatchNotFail(c byte, matcher *zone.Matcher, t *testing.T) {
	if !matcher.Match(c) {
		t.Fatal("Unexpected unmatch")
	}
}

type TestKeyStore struct{}

func (*TestKeyStore) RotateZoneKey(zoneID []byte) ([]byte, error) {
	panic("implement me")
}
func (storage *TestKeyStore) GetZonePrivateKey(id []byte) (*keys.PrivateKey, error) {
	return &keys.PrivateKey{Value: []byte{}}, nil
}
func (storage *TestKeyStore) HasZonePrivateKey(id []byte) bool { return true }
func (storage *TestKeyStore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	return &keys.PublicKey{Value: []byte{}}, nil
}
func (storage *TestKeyStore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	return &keys.PrivateKey{Value: []byte{}}, nil
}
func (storage *TestKeyStore) GenerateZoneKey() ([]byte, []byte, error) { return []byte{}, []byte{}, nil }

func (storage *TestKeyStore) Reset()                                     {}
func (storage *TestKeyStore) GenerateConnectorKeys(id []byte) error      { return nil }
func (storage *TestKeyStore) GenerateServerKeys(id []byte) error         { return nil }
func (storage *TestKeyStore) GenerateTranslatorKeys(id []byte) error     { return nil }
func (storage *TestKeyStore) GenerateDataEncryptionKeys(id []byte) error { return nil }
func (storage *TestKeyStore) GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error) {
	return nil, nil
}
func (keystore *TestKeyStore) GetAuthKey(remove bool) ([]byte, error) {
	return nil, nil
}
func (storage *TestKeyStore) GetPoisonKeyPair() (*keys.Keypair, error) { return nil, nil }
func (*TestKeyStore) SaveDataEncryptionKeys(id []byte, keypair *keys.Keypair) error {
	panic("implement me")
}
func (*TestKeyStore) SaveTranslatorKeypair(id []byte, keypair *keys.Keypair) error {
	panic("implement me")
}
func (*TestKeyStore) SaveServerKeypair(id []byte, keypair *keys.Keypair) error { panic("implement me") }
func (*TestKeyStore) SaveConnectorKeypair(id []byte, keypair *keys.Keypair) error {
	panic("implement me")
}
func (*TestKeyStore) SaveZoneKeypair(id []byte, keypair *keys.Keypair) error  { panic("implement me") }
func (*TestKeyStore) GetZonePublicKey(zoneID []byte) (*keys.PublicKey, error) { panic("implement me") }
func (*TestKeyStore) GetClientIDEncryptionPublicKey(clientID []byte) (*keys.PublicKey, error) {
	panic("implement me")
}

func testZoneIDMatcher(t *testing.T) {
	var keystorage keystore.PrivateKeyStore = &TestKeyStore{}
	matcherPool := zone.NewMatcherPool(zone.NewPgMatcherFactory())
	zoneMatcher := zone.NewZoneMatcher(matcherPool, keystorage)

	// test correct matching
	t.Log("Check zone id")
	for _, c := range zone.ZoneIDBegin {
		assertZoneMatchNotFail(byte(c), zoneMatcher, t)
	}
	// fill zone id
	for i := 0; i < (zone.ZoneIDLength); i++ {
		assertZoneMatchNotFail('a', zoneMatcher, t)
	}

	if !zoneMatcher.IsMatched() {
		t.Fatal("Expected matched status")
		return
	}
	zoneMatcher.Reset()

	// test correct matching inner zone id
	t.Log("Check inner zone id")
	// feed correct tag begin
	for _, c := range zone.ZoneIDBegin {
		assertZoneMatchNotFail(byte(c), zoneMatcher, t)
	}
	// feed half of correct zone id
	for i := 0; i < zone.ZoneIDLength; i++ {
		assertZoneMatchNotFail('a', zoneMatcher, t)
	}

	// feed second correct tag begin in zone_id block
	for _, c := range zone.ZoneIDBegin {
		assertZoneMatchNotFail(byte(c), zoneMatcher, t)
	}
	// feed correct zone id
	for i := 0; i < (zone.ZoneIDLength); i++ {
		assertZoneMatchNotFail('a', zoneMatcher, t)
	}

	if !zoneMatcher.IsMatched() {
		t.Fatal("Expected matched status")
		return
	}
}

func TestZoneIDMatcher(t *testing.T) {
	testZoneIDMatcher(t)
}
