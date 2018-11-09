/*
Copyright 2018, Cossack Labs Limited

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

package postgresql

import (
	"bytes"
	"errors"
)

var terminator = []byte{0}
var ErrTerminatorNotFound = errors.New("invalid string, terminator not found")

// FetchQueryFromParse return Query value from Parse packet payload (without message type and length of packet)
//
// Find first null terminator as end of prepared statement name and find next which terminate query string
// Parse packet has next structure: 'P' + int32 (length of packet) + NullTerminatedString (prepared statement name) +
// + NullTerminatedString (query) + int16 (number of next int32 parameters) + int32[n] (parameters)
// https://www.postgresql.org/docs/9.3/protocol-message-formats.html
func FetchQueryFromParse(data []byte) ([]byte, error) {
	startIndex := bytes.Index(data, terminator)
	if startIndex == -1 {
		return nil, ErrTerminatorNotFound
	}
	// skip terminator of previous field
	startIndex += 1
	endIndex := bytes.Index(data[startIndex:], terminator)
	if endIndex == -1 {
		return nil, ErrTerminatorNotFound
	}
	// convert to absolute
	endIndex += startIndex
	return data[startIndex : endIndex+1], nil
}
