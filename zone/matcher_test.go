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
package zone

import (
	"testing"
)

func assertMatchFail(c byte, matcher matcher, t *testing.T) {
	if matcher.Match(c) {
		t.Fatalf("Expected match fail on char %v", string(c))
	}
	if matcher.IsMatched() {
		t.Fatal("Unexpected matched status")
	}
}
func assertMatchNotFail(c byte, matcher matcher, t *testing.T) {
	if !matcher.Match(c) {
		t.Fatal("Unexpected unmatch")
	}
}

func testMatcherWithBinaryReader(t *testing.T) {
	matcher := newBaseMatcher(NewBinaryByteReader())
	// test fail on first char of tab begin
	assertMatchFail('q', matcher, t)
	matcher.Reset()

	// test fail on last char of tag begin
	for _, c := range ZoneIDBegin[:len(ZoneIDBegin)-1] {
		assertMatchNotFail(byte(c), matcher, t)
	}
	assertMatchFail('q', matcher, t)
	matcher.Reset()

	// test correct matching
	for _, c := range ZoneIDBegin {
		assertMatchNotFail(byte(c), matcher, t)
	}
	// fill zone id
	for i := 0; i < ZoneIDLength; i++ {
		assertMatchNotFail('a', matcher, t)
	}

	if !matcher.IsMatched() {
		t.Fatal("Expected matched status")
	}
}

func testHasAnyMatchWithBinaryReader(t *testing.T) {
	matcher := newBaseMatcher(NewBinaryByteReader())
	if matcher.HasAnyMatch() {
		t.Fatal("Expected no match")
	}
	if !matcher.Match(ZoneIDBegin[0]) {
		t.Fatal("Expected match")
	}
	if !matcher.HasAnyMatch() {
		t.Fatal("Expected match")
	}
	if !matcher.Match(ZoneIDBegin[1]) {
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
	pgMatcher := newPgMatcher(NewBinaryByteReader())
	t.Log("Test binary zone id")
	t.Log("Fill zone begin")
	// test correct matching with binary zone_id
	for _, c := range ZoneIDBegin {
		assertMatchNotFail(byte(c), pgMatcher, t)
	}
	t.Log("Fill zone id")
	// fill zone id
	for i := 0; i < ZoneIDLength; i++ {
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
}

func TestMatcher(t *testing.T) {
	testMatcherWithBinaryReader(t)
	testHasAnyMatchWithBinaryReader(t)
	testPgMatcher(t)
}
