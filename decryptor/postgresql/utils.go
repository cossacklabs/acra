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
	"encoding/binary"
	"errors"
)

var terminator = []byte{0}

// ErrTerminatorNotFound not found terminator for string value
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
	startIndex++
	endIndex := bytes.Index(data[startIndex:], terminator)
	if endIndex == -1 {
		return nil, ErrTerminatorNotFound
	}
	// convert to absolute
	endIndex += startIndex
	return data[startIndex : endIndex+1], nil
}

type objectID []byte
type paramsNum []byte

// ToInt convert byte array to int
func (num paramsNum) ToInt() int {
	return int(binary.BigEndian.Uint16(num))
}

// ParsePacket store data related with Parse postgresql message
type ParsePacket struct {
	name  []byte
	query []byte
	// int16
	paramsNum paramsNum
	// []int32
	params []objectID
}

// Marshal packet to bytes
func (packet *ParsePacket) Marshal() []byte {
	output := make([]byte, 0, packet.Length())
	output = append(output, packet.name...)
	output = append(output, packet.query...)
	output = append(output, packet.paramsNum...)
	for _, param := range packet.params {
		output = append(output, param...)
	}
	return output
}

// Length return total length of packet
func (packet *ParsePacket) Length() int {
	return len(packet.name) + len(packet.query) + len(packet.paramsNum) + (4 * len(packet.params))
}

// Name returns requested prepared statement name.
// Note that empty string is a valid value indicating unnamed prepared statement.
func (packet *ParsePacket) Name() string {
	// Trailing null byte is included into the slice for faster Marshal().
	return string(packet.name[:len(packet.name)-1])
}

// QueryString return query as string
func (packet *ParsePacket) QueryString() string {
	// Trailing null byte is included into the slice for faster Marshal().
	return string(packet.query[:len(packet.query)-1])
}

// ReplaceQuery with new query
func (packet *ParsePacket) ReplaceQuery(newQuery string) {
	packet.query = append([]byte(newQuery), 0)
}

// NewParsePacket parse data and return as ParsePacket or error
func NewParsePacket(data []byte) (*ParsePacket, error) {
	startIndex := bytes.Index(data, terminator)
	if startIndex == -1 {
		return nil, ErrTerminatorNotFound
	}
	startIndex++
	name := data[:startIndex]
	// skip terminator of previous field
	endIndex := bytes.Index(data[startIndex:], terminator)
	if endIndex == -1 {
		return nil, ErrTerminatorNotFound
	}
	// convert to absolute
	endIndex += startIndex + 1
	query := data[startIndex:endIndex]
	numParams := paramsNum(data[endIndex : endIndex+2])
	endIndex += 2
	var params []objectID
	if endIndex < len(data) {
		for i := 0; i < numParams.ToInt(); i++ {
			params = append(params, data[endIndex:endIndex+4])
			endIndex += 4
		}
	}
	return &ParsePacket{
		name:      name,
		query:     query,
		paramsNum: numParams,
		params:    params,
	}, nil

}
