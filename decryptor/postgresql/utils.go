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

// ErrPacketTruncated signals that the packet is too short and cannot be parsed
var ErrPacketTruncated = errors.New("invalid packet, too short")

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

// BindPacket represents "Bind" packet of the PostgreSQL protocol,
// containing bound parameters of a prepared statement.
// See https://www.postgresql.org/docs/current/protocol-message-formats.html
type BindPacket struct {
	portal        string
	statement     string
	paramFormats  []uint16
	paramValues   [][]byte
	resultFormats []uint16
}

// PortalName returns the name of the portal created by this request.
// An empty name means unnamed portal.
func (p *BindPacket) PortalName() string {
	return p.portal
}

// StatementName returns the name of the statement bound by this request.
// An empty name means unnamed statement.
func (p *BindPacket) StatementName() string {
	return p.statement
}

// NewBindPacket parses Bind packet from data.
func NewBindPacket(data []byte) (*BindPacket, error) {
	portal, data, err := readString(data)
	if err != nil {
		return nil, err
	}
	statement, data, err := readString(data)
	if err != nil {
		return nil, err
	}
	paramFormats, data, err := readUint16Array(data)
	if err != nil {
		return nil, err
	}
	paramValues, data, err := readParameterArray(data)
	if err != nil {
		return nil, err
	}
	resultFormats, data, err := readUint16Array(data)
	if err != nil {
		return nil, err
	}
	return &BindPacket{
		portal:        portal,
		statement:     statement,
		paramFormats:  paramFormats,
		paramValues:   paramValues,
		resultFormats: resultFormats,
	}, nil
}

// ExecutePacket represents "Execute" packet of the PostgreSQL protocol,
// containing the name of the portal to query for data.
// See https://www.postgresql.org/docs/current/protocol-message-formats.html
type ExecutePacket struct {
	portal  string
	maxRows uint32
}

// PortalName returns the name of the portal queried by this request.
// An empty name means unnamed portal.
func (p *ExecutePacket) PortalName() string {
	return p.portal
}

// NewExecutePacket parses Executre packet from data.
func NewExecutePacket(data []byte) (*ExecutePacket, error) {
	portal, data, err := readString(data)
	if err != nil {
		return nil, err
	}
	maxRows := binary.BigEndian.Uint32(data)
	return &ExecutePacket{portal, maxRows}, nil
}

func readString(data []byte) (string, []byte, error) {
	// Read null-terminated string, don't include the terminator into value.
	end := bytes.Index(data, terminator)
	if end == -1 {
		return "", data, ErrTerminatorNotFound
	}
	return string(data[:end]), data[end+1:], nil
}

func readUint16Array(data []byte) ([]uint16, []byte, error) {
	remaining := data
	// The []uint16 array is prefixed with a number of its items, also a uint16.
	if len(remaining) < 2 {
		return nil, data, ErrPacketTruncated
	}
	itemCount := int(binary.BigEndian.Uint16(remaining[:2]))
	remaining = remaining[2:]

	if len(remaining) < 2*itemCount {
		return nil, data, ErrPacketTruncated
	}
	items := make([]uint16, itemCount)
	for i := range items {
		items[i] = binary.BigEndian.Uint16(remaining[:2])
		remaining = remaining[2:]
	}

	return items, remaining, nil
}

func readParameterArray(data []byte) ([][]byte, []byte, error) {
	remaining := data
	// The array is prefixed with a number of its items, a uint16.
	if len(remaining) < 2 {
		return nil, data, ErrPacketTruncated
	}
	parameterCount := int(binary.BigEndian.Uint16(remaining[:2]))
	remaining = remaining[2:]

	// Each parameter is a pair of value length (uint32) followed by value bytes.
	parameters := make([][]byte, parameterCount)
	for i := range parameters {
		if len(remaining) < 4 {
			return nil, data, ErrPacketTruncated
		}
		parameterLen := int(binary.BigEndian.Uint32(remaining[:4]))
		remaining = remaining[4:]

		// NULL value is a special case. No parameter bytes follow it.
		// The length is actually -1 but we read two's complement as uint32.
		if parameterLen == 0xFFFFFFFF {
			continue
		}

		if len(remaining) < parameterLen {
			return nil, data, ErrPacketTruncated
		}
		parameters[i] = remaining[:parameterLen]
		remaining = remaining[parameterLen:]
	}

	return parameters, remaining, nil
}
