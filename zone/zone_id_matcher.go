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
	"bytes"
	"context"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/sirupsen/logrus"
)

// should be used ascii symbols as prefix/suffix for using as output and filenames

// were chosen upper symbols because if data is text than it's less possible to
// catch three upper consonants in a row
// var ZoneIDBegin = []byte{'Z', 'X', 'C'}
// '44' - D - 68 - 0b1000100
var (
	ZoneTagSymbol     byte = 'D'
	ZoneIDBegin            = []byte{ZoneTagSymbol, ZoneTagSymbol, ZoneTagSymbol, ZoneTagSymbol, ZoneTagSymbol, ZoneTagSymbol, ZoneTagSymbol, ZoneTagSymbol}
	ZoneTagLength          = len(ZoneIDBegin)
	ZoneIDLength           = 16
	ZoneIDBlockLength      = int(ZoneTagLength + ZoneIDLength)
)

// KeyChecker checks if Zone Private key is available
type KeyChecker interface {
	HasZonePrivateKey([]byte) bool
}

// Matcher represents exact binary matcher
type Matcher struct {
	zoneID     []byte
	keychecker KeyChecker
}

// NewZoneMatcher returns new Matcher for exact zoneID
// with keychecker and empty matchers
func NewZoneMatcher(keychecker KeyChecker) *Matcher {
	matcher := &Matcher{
		keychecker: keychecker,
	}
	return matcher
}

// IsMatched returns true if zoneID found
func (zoneMatcher *Matcher) IsMatched() bool {
	return zoneMatcher.zoneID != nil
}

// Reset clears matchers and reset matching state
func (zoneMatcher *Matcher) Reset() {
	zoneMatcher.zoneID = nil
}

// GetZoneID returns zoneID if matched found it
// return empty bytes otherwise
func (zoneMatcher *Matcher) GetZoneID() []byte {
	return zoneMatcher.zoneID
}

// SetMatched sets that matcher has found zoneID – id
func (zoneMatcher *Matcher) SetMatched(id []byte) {
	zoneMatcher.zoneID = id
}

// Match returns true if zoneID found inside c bytes
// checks using different matchers from the loop
func (zoneMatcher *Matcher) Match(data []byte) bool {
	if !bytes.HasPrefix(data, ZoneIDBegin) {
		return false
	}
	if zoneMatcher.keychecker.HasZonePrivateKey(data) {
		zoneMatcher.zoneID = data
		return true
	}
	return false
}

// OnColumn try to match ZoneID in data and set it to AccessContext on success
func (zoneMatcher *Matcher) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	if zoneMatcher.Match(data) {
		accessContext := base.AccessContextFromContext(ctx)
		accessContext.SetZoneID(zoneMatcher.zoneID)
		logrus.Debugln("Matched in zonematcher")
	}
	return ctx, data, nil
}

// ID return Matcher's ID
func (zoneMatcher *Matcher) ID() string {
	return "ZoneIDMatcher"
}
