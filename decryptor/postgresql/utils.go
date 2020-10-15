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
	"math"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

var terminator = []byte{0}

// ErrTerminatorNotFound not found terminator for string value
var ErrTerminatorNotFound = errors.New("invalid string, terminator not found")

// ErrPacketTruncated signals that the packet is too short and cannot be parsed
var ErrPacketTruncated = errors.New("invalid packet, too short")

// ErrArrayTooBig signals that an array it too big to fit into a packet.
var ErrArrayTooBig = errors.New("array too big")

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

// Zeroize sensitive data in the packet.
func (packet *ParsePacket) Zeroize() {
	utils.ZeroizeBytes(packet.query)
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

// ErrUnknownFormat is returned when Bind packet contains a value format that we don't recognize.
var ErrUnknownFormat = errors.New("unknown Bind packet format")

// ErrNotEnougFormats is returned when Bind packet is malformed and does not contain enough formats for values.
var ErrNotEnougFormats = errors.New("format index out of range")

const (
	bindFormatText   = 0
	bindFormatBinary = 1
)

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

// Zeroize sensitive data in the packet.
func (p *BindPacket) Zeroize() {
	for _, value := range p.paramValues {
		utils.ZeroizeBytes(value)
	}
}

// GetParameters extracts statement parameters from Bind packet.
func (p *BindPacket) GetParameters() ([]base.BoundValue, error) {
	values := make([]base.BoundValue, len(p.paramValues))
	for i := range values {
		encoding, err := p.parameterEncodingByIndex(i)
		if err != nil {
			return nil, err
		}
		values[i] = base.NewBoundValue(p.paramValues[i], encoding)
	}
	return values, nil
}

func (p *BindPacket) parameterEncodingByIndex(i int) (base.BoundValueEncoding, error) {
	// See "Bind" description in https://www.postgresql.org/docs/current/protocol-message-formats.html
	// If there are no formats then all values use the default: text.
	if len(p.paramFormats) == 0 {
		return base.BindText, nil
	}
	// If there is only one format then it is used for all values.
	var format uint16
	if len(p.paramFormats) == 1 {
		format = p.paramFormats[0]
	} else if i < len(p.paramFormats) {
		format = p.paramFormats[i]
	} else {
		log.WithField("index", i).WithField("max", len(p.paramFormats)).Debug("Bind format array too short")
		return base.BindText, ErrNotEnougFormats
	}
	// Options currently include text and binary formats.
	switch format {
	case bindFormatText:
		return base.BindText, nil
	case bindFormatBinary:
		return base.BindBinary, nil
	default:
		log.WithField("index", i).WithField("format", format).Debug("Unknown Bind format")
		return base.BindText, ErrUnknownFormat
	}
}

// SetParameters updates statement parameters from Bind packet.
func (p *BindPacket) SetParameters(values []base.BoundValue) {
	// See "Bind" description in https://www.postgresql.org/docs/current/protocol-message-formats.html
	// If there are no parameters then don't bother.
	if len(values) == 0 {
		p.paramFormats = nil
		return
	}
	// Check if all parameters have the same format. We can optimize storage if that's true.
	allSame := true
	encoding := base.BindText
	if len(values) > 0 {
		encoding = values[0].Encoding()
		for _, value := range values[1:] {
			if value.Encoding() != encoding {
				allSame = false
				break
			}
		}
	}
	// If all parameters have the same encoding then mention it only once.
	// Otherwise, we need to explicitly specify formats.
	if allSame {
		p.paramFormats = make([]uint16, 1)
		switch encoding {
		case base.BindText:
			p.paramFormats[0] = bindFormatText
		case base.BindBinary:
			p.paramFormats[0] = bindFormatBinary
		}
	} else {
		p.paramFormats = make([]uint16, len(values))
		for i := range p.paramFormats {
			switch values[i].Encoding() {
			case base.BindText:
				p.paramFormats[i] = bindFormatText
			case base.BindBinary:
				p.paramFormats[i] = bindFormatBinary
			}
		}
	}
	// Finally, replace parameter values. Reuse the top-level array if we can.
	if len(values) != len(p.paramValues) {
		p.paramValues = make([][]byte, len(values))
	}
	for i := range p.paramValues {
		p.paramValues[i] = values[i].Data()
	}
}

// MarshalInto packet contents into packet protocol data buffer.
func (p *BindPacket) MarshalInto(buffer *bytes.Buffer) (int, error) {
	var total int
	oldLength := buffer.Len()

	n, err := writeString(buffer, p.portal)
	if err != nil {
		buffer.Truncate(oldLength)
		return 0, err
	}
	total += n

	n, err = writeString(buffer, p.statement)
	if err != nil {
		buffer.Truncate(oldLength)
		return 0, err
	}
	total += n

	n, err = writeUint16Array(buffer, p.paramFormats)
	if err != nil {
		buffer.Truncate(oldLength)
		return 0, err
	}
	total += n

	n, err = writeParameterArray(buffer, p.paramValues)
	if err != nil {
		buffer.Truncate(oldLength)
		return 0, err
	}
	total += n

	n, err = writeUint16Array(buffer, p.resultFormats)
	if err != nil {
		buffer.Truncate(oldLength)
		return 0, err
	}
	total += n

	return total, nil
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
	resultFormats, _, err := readUint16Array(data)
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

// Zeroize sensitive data in the packet.
func (p *ExecutePacket) Zeroize() {
}

// NewExecutePacket parses Execute packet from data.
func NewExecutePacket(data []byte) (*ExecutePacket, error) {
	portal, data, err := readString(data)
	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, ErrPacketTruncated
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

func writeString(buf *bytes.Buffer, s string) (int, error) {
	buf.Grow(len(s) + 1)
	buf.WriteString(s)
	buf.WriteByte(0)
	return len(s) + 1, nil
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

func writeUint16Array(buf *bytes.Buffer, values []uint16) (int, error) {
	totalLength := 2 + len(values)*2
	buf.Grow(totalLength)

	tmp := make([]byte, 2)
	if len(values) > math.MaxUint16 {
		return 0, ErrArrayTooBig
	}
	binary.BigEndian.PutUint16(tmp, uint16(len(values)))
	buf.Write(tmp)

	for _, value := range values {
		binary.BigEndian.PutUint16(tmp, value)
		buf.Write(tmp)
	}

	return totalLength, nil
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

func writeParameterArray(buf *bytes.Buffer, parameters [][]byte) (int, error) {
	totalLength := 2
	for _, parameter := range parameters {
		totalLength += 4 + len(parameter)
	}
	buf.Grow(totalLength)

	tmp := make([]byte, 4)
	if len(parameters) > math.MaxUint16 {
		return 0, ErrArrayTooBig
	}
	binary.BigEndian.PutUint16(tmp[0:2], uint16(len(parameters)))
	buf.Write(tmp[0:2])

	for _, parameter := range parameters {
		if len(parameter) > math.MaxUint32 {
			return 0, ErrArrayTooBig
		}
		binary.BigEndian.PutUint32(tmp[0:4], uint32(len(parameter)))
		buf.Write(tmp[0:4])
		buf.Write(parameter)
	}

	return totalLength, nil
}
