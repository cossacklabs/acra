// Package zone_test contains tests for Zone matchers.
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
package zone_test

import (
	"encoding/hex"
	"github.com/cossacklabs/acra/zone"
	"testing"
)

func assertMatchFail(c byte, matcher zone.Matcher, t *testing.T) {
	if matcher.Match(c) {
		t.Fatalf("Expected match fail on char %v", string(c))
	}
	if matcher.IsMatched() {
		t.Fatal("Unexpected matched status")
	}
}
func assertMatchNotFail(c byte, matcher zone.Matcher, t *testing.T) {
	if !matcher.Match(c) {
		t.Fatal("Unexpected unmatch")
	}
}

func testMatcherWithHexReader(t *testing.T) {
	matcher := zone.NewPgHexMatcherFactory().CreateMatcher()
	// we neen explicit "end" for escape format where zone_id has dynamic size
	// 973feb
	var HEX_ZONE_ID_BEGIN = []byte(hex.EncodeToString(zone.ZONE_ID_BEGIN))

	// test fail on first char of tab begin
	assertMatchFail('q', matcher, t)
	matcher.Reset()

	// test fail on last char of tag begin
	for _, c := range HEX_ZONE_ID_BEGIN[:len(HEX_ZONE_ID_BEGIN)-1] {
		assertMatchNotFail(byte(c), matcher, t)
	}
	assertMatchFail('q', matcher, t)
	matcher.Reset()

	// test fail on incorrect char in zone_id block
	for _, c := range HEX_ZONE_ID_BEGIN {
		assertMatchNotFail(byte(c), matcher, t)
	}
	// 4 correct digits
	for _, c := range []byte{'a', 'B', 'F', '0'} {
		assertMatchNotFail(byte(c), matcher, t)
	}
	assertMatchFail('q', matcher, t)
	matcher.Reset()

	// test correct matching
	for _, c := range HEX_ZONE_ID_BEGIN {
		assertMatchNotFail(byte(c), matcher, t)
	}
	// fill zone id
	for i := 0; i < (zone.ZONE_ID_LENGTH * 2); i++ {
		assertMatchNotFail('a', matcher, t)
	}

	if !matcher.IsMatched() {
		t.Fatal("Expected matched status")
	}
}

func testMatcherWithEscapeReader(t *testing.T) {
	matcher := zone.NewBaseMatcher(zone.NewPgEscapeByteReader())
	var INCORRECT_VALUE byte = 31

	t.Log("Test fail on first char of begin tag")
	assertMatchFail(INCORRECT_VALUE, matcher, t)
	matcher.Reset()

	t.Log("Test fail on last char of begin tag")
	for _, c := range zone.ZONE_ID_BEGIN[:len(zone.ZONE_ID_BEGIN)-1] {
		assertMatchNotFail(byte(c), matcher, t)
	}
	assertMatchFail(INCORRECT_VALUE, matcher, t)
	matcher.Reset()

	t.Log("Test fail on incorrect char in zone_id block")
	for _, c := range zone.ZONE_ID_BEGIN {
		assertMatchNotFail(byte(c), matcher, t)
	}
	// 4 correct printable digits
	for _, c := range []byte{'a', 'B', 'F', '0'} {
		assertMatchNotFail(byte(c), matcher, t)
	}
	// test 1 non printable value
	assertMatchNotFail('\\', matcher, t)
	assertMatchNotFail('0', matcher, t)
	assertMatchNotFail('0', matcher, t)
	assertMatchNotFail('1', matcher, t)

	assertMatchFail(INCORRECT_VALUE, matcher, t)
	matcher.Reset()

	t.Log("Test correct matching")
	for _, c := range zone.ZONE_ID_BEGIN {
		assertMatchNotFail(byte(c), matcher, t)
	}
	// fill zone id
	for i := 0; i < zone.ZONE_ID_LENGTH; i++ {
		assertMatchNotFail('a', matcher, t)
	}
	if !matcher.IsMatched() {
		t.Fatal("Expected matched status")
	}
}

func testMatcherWithBinaryReader(t *testing.T) {
	matcher := zone.NewBaseMatcher(zone.NewBinaryByteReader())
	// test fail on first char of tab begin
	assertMatchFail('q', matcher, t)
	matcher.Reset()

	// test fail on last char of tag begin
	for _, c := range zone.ZONE_ID_BEGIN[:len(zone.ZONE_ID_BEGIN)-1] {
		assertMatchNotFail(byte(c), matcher, t)
	}
	assertMatchFail('q', matcher, t)
	matcher.Reset()

	// test correct matching
	for _, c := range zone.ZONE_ID_BEGIN {
		assertMatchNotFail(byte(c), matcher, t)
	}
	// fill zone id
	for i := 0; i < zone.ZONE_ID_LENGTH; i++ {
		assertMatchNotFail('a', matcher, t)
	}

	if !matcher.IsMatched() {
		t.Fatal("Expected matched status")
	}
}

func testHasAnyMatchWithHexReader(t *testing.T) {
	factory := zone.NewPgHexMatcherFactory()
	matcher := factory.CreateMatcher()
	var HEX_ZONE_ID_BEGIN = []byte(hex.EncodeToString(zone.ZONE_ID_BEGIN))
	if matcher.HasAnyMatch() {
		t.Fatal("Expected no match")
	}
	matcher.Match(HEX_ZONE_ID_BEGIN[0])
	if !matcher.HasAnyMatch() {
		t.Fatal("Expected no match")
	}
	matcher.Match(HEX_ZONE_ID_BEGIN[1])
	if !matcher.HasAnyMatch() {
		t.Fatal("Expected no match")
	}

	matcher = factory.CreateMatcher()
	incorrectByte := byte(1)
	matcher.Match(incorrectByte)
	if matcher.HasAnyMatch() {
		t.Fatal("Expected no match")
	}
}

func testHasAnyMatchWithEscapeReader(t *testing.T) {
	factory := zone.NewPgEscapeMatcherFactory()
	matcher := factory.CreateMatcher()
	if matcher.HasAnyMatch() {
		t.Fatal("Expected no match")
	}
	// test first octal value from zone_id_begin
	for _, c := range zone.ZONE_ID_BEGIN[:3] {
		matcher.Match(c)
		if !matcher.HasAnyMatch() {
			t.Fatal("Unexpected no match")
		}
	}

	matcher = factory.CreateMatcher()
	incorrectByte := byte(1)
	matcher.Match(incorrectByte)
	if matcher.HasAnyMatch() {
		t.Fatal("Expected no match")
	}
}

func testHasAnyMatchWithBinaryReader(t *testing.T) {
	matcher := zone.NewBaseMatcher(zone.NewBinaryByteReader())
	if matcher.HasAnyMatch() {
		t.Fatal("Expected no match")
	}
	if !matcher.Match(zone.ZONE_ID_BEGIN[0]) {
		t.Fatal("Expected match")
	}
	if !matcher.HasAnyMatch() {
		t.Fatal("Expected match")
	}
	if !matcher.Match(zone.ZONE_ID_BEGIN[1]) {
		t.Fatal("Expected match")
	}
	if !matcher.HasAnyMatch() {
		t.Fatal("Expected no match")
	}
	matcher.Reset()
	incorrectByte := byte(1)
	if matcher.Match(incorrectByte) {
		t.Fatal("Expected no match")
	}
	if matcher.HasAnyMatch() {
		t.Fatal("Expected no match")
	}
}

func testPgMatcher(t *testing.T) {
	pgMatcher := zone.NewPgMatcher(zone.NewPgHexByteReader())
	t.Log("Test binary zone id")
	t.Log("Fill zone begin")
	// test correct matching with binary zone_id
	for _, c := range zone.ZONE_ID_BEGIN {
		assertMatchNotFail(byte(c), pgMatcher, t)
	}
	t.Log("Fill zone id")
	// fill zone id
	for i := 0; i < zone.ZONE_ID_LENGTH; i++ {
		t.Log("Fill ", i)
		assertMatchNotFail('a', pgMatcher, t)
	}
	t.Log("Check matched")
	if !pgMatcher.IsMatched() {
		t.Fatal("Unexpected unmatched status")
	}
	pgMatcher.Reset()
	incorrectFirstByte := byte(1)
	if pgMatcher.Match(incorrectFirstByte) || pgMatcher.HasAnyMatch() {
		t.Fatal("Unexpected match")
	}
	pgMatcher.Reset()
	var HEX_ZONE_ID_BEGIN = []byte(hex.EncodeToString(zone.ZONE_ID_BEGIN))
	t.Log("Test hex zone id")
	for _, c := range HEX_ZONE_ID_BEGIN {
		assertMatchNotFail(byte(c), pgMatcher, t)
	}
	// fill zone id
	for i := 0; i < (zone.ZONE_ID_LENGTH * 2); i++ {
		assertMatchNotFail('a', pgMatcher, t)
	}

	if !pgMatcher.IsMatched() {
		t.Fatal("Expected matched status")
	}

}

func TestMatcher(t *testing.T) {
	testMatcherWithHexReader(t)
	testHasAnyMatchWithHexReader(t)
	testMatcherWithEscapeReader(t)
	testHasAnyMatchWithEscapeReader(t)
	testMatcherWithBinaryReader(t)
	testHasAnyMatchWithBinaryReader(t)
	testPgMatcher(t)
}
