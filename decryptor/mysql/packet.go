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

package mysql

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/cossacklabs/acra/decryptor/base"
	base_mysql "github.com/cossacklabs/acra/decryptor/mysql/base"
)

// MySQL protocol capability flags https://dev.mysql.com/doc/internals/en/capability-flags.html
const (
	// ClientProtocol41 - https://dev.mysql.com/doc/internals/en/capability-flags.html#flag-CLIENT_PROTOCOL_41
	ClientProtocol41 = 0x00000200
	// SslRequest - https://dev.mysql.com/doc/internals/en/capability-flags.html#flag-CLIENT_SSL
	SslRequest = 0x00000800
	// ClientDeprecateEOF - https://dev.mysql.com/doc/internals/en/capability-flags.html#flag-CLIENT_DEPRECATE_EOF - 0x1000000
	ClientDeprecateEOF = 0x01000000
)

// MySQL packets significant bytes.
const (
	// OkPacket - https://dev.mysql.com/doc/internals/en/packet-OK_Packet.html
	OkPacket = 0x00
	// EOFPacket - https://dev.mysql.com/doc/internals/en/packet-EOF_Packet.html
	EOFPacket = 0xfe
	ErrPacket = 0xff
)

const (
	// PacketHeaderSize https://dev.mysql.com/doc/internals/en/mysql-packet.html#idm140406396409840
	PacketHeaderSize = 4
	// SequenceIDIndex last byte of header https://dev.mysql.com/doc/internals/en/mysql-packet.html#idm140406396409840
	SequenceIDIndex = 3
)

// Describe values that represent signed/unsigned identifier for MySQL numeric type inside packet.
// https://dev.mysql.com/doc/internals/en/com-stmt-execute.html
const (
	signedBinaryValue = 0
	// flag byte which has the highest bit set if the type is unsigned.
	unsignedBinaryValue = 0b1000_0000
)

// ErrPacketHasNotExtendedCapabilities if packet has capability flags
var ErrPacketHasNotExtendedCapabilities = errors.New("packet hasn't extended capabilities")

// Dumper dumps :)
type Dumper interface {
	Dump() []byte
}

// ByteArrayDump array
type ByteArrayDump []byte

// Dump returns array
func (array ByteArrayDump) Dump() []byte {
	return array
}

// Packet struct that store header and payload, reads it from connection
type Packet struct {
	header []byte
	data   []byte
}

// NewPacket returns new Packet
func NewPacket() *Packet {
	// https://dev.mysql.com/doc/internals/en/mysql-packet.html#idm140406396409840
	// 3 bytes payload length and 1 byte of sequence_id
	return &Packet{header: make([]byte, PacketHeaderSize)}
}

// GetPacketPayloadLength returns payload length from first 3 bytes of header
func (packet *Packet) GetPacketPayloadLength() int {
	// first 3 bytes of header
	// https://dev.mysql.com/doc/internals/en/mysql-packet.html#idm140406396409840
	return int(uint32(packet.header[0]) | uint32(packet.header[1])<<8 | uint32(packet.header[2])<<16)
}

// GetSequenceNumber returned as byte
func (packet *Packet) GetSequenceNumber() byte {
	return packet.header[SequenceIDIndex]
}

// GetData returns packet payload
func (packet *Packet) GetData() []byte {
	return packet.data
}

// GetBindParameters returns packet Bind parameters
func (packet *Packet) GetBindParameters(paramNum int) ([]base.BoundValue, error) {
	// https://dev.mysql.com/doc/internals/en/com-stmt-execute.html#packet-COM_STMT_EXECUTE
	// 1 - packet header
	// 4 - stmt-id
	// 1 - flags
	// 4 - iteration-count
	pos := 10
	if paramNum > 0 {
		// 7 + num-params offset from docs
		pos = 10 + ((paramNum + 7) >> 3)
	}

	values := make([]base.BoundValue, paramNum)
	// new-params-bound-flag
	if packet.data[pos] != 1 {
		return values, nil
	}
	pos += +1

	//here we need to gather all provided param types
	paramTypes := make([]byte, paramNum)
	for i := 0; i < paramNum; i++ {
		paramTypes[i] = packet.data[pos]
		pos += 2
	}

	for i := 0; i < paramNum; i++ {
		boundValue, n, err := NewMysqlBoundValue(packet.data[pos:], base.BinaryFormat, base_mysql.Type(paramTypes[i]))
		if err != nil {
			return nil, err
		}
		values[i] = boundValue
		pos += n
	}

	return values, nil
}

// SetParameters updates statement parameters from Bind packet.
func (packet *Packet) SetParameters(values []base.BoundValue) (err error) {
	// If there are no parameters then don't bother.
	if len(values) == 0 {
		return nil
	}

	// https://dev.mysql.com/doc/internals/en/com-stmt-execute.html#packet-COM_STMT_EXECUTE
	// 1 - packet header
	// 4 - stmt-id
	// 1 - flags
	// 4 - iteration-count
	pos := 10

	// NULL-bitmap, length: (num-params+7)/8
	// new-params-bound-flag
	pos += (len(values)+7)>>3 + 1

	resultData := make([]byte, len(packet.data[:pos]), len(packet.data))
	copy(resultData, packet.data[:pos])

	// params amount shift
	for i := 0; i < len(values); i++ {
		paramType := packet.data[pos : pos+2]
		boundType := values[i].GetType()

		// we need to check if the type was changed during tokenization
		if paramType[0] != boundType {
			paramType[0] = boundType
		}

		// potential tokenization happened before
		// and we need to get result tokenization value to set signed/unsigned byte
		switch base_mysql.Type(boundType) {
		case base_mysql.TypeLong, base_mysql.TypeLongLong:
			data, err := values[i].GetData(nil)
			if err != nil {
				return err
			}
			intValue, err := strconv.ParseInt(string(data), 10, 64)
			if err != nil {
				return err
			}

			paramType[1] = unsignedBinaryValue
			if intValue < 0 {
				paramType[1] = signedBinaryValue
			}
		}

		resultData = append(resultData, paramType...)
		pos += 2
	}

	for i := 0; i < len(values); i++ {
		encoded, err := values[i].Encode()
		if err != nil {
			return err
		}

		resultData = append(resultData, encoded...)
	}

	packet.SetData(resultData)
	return nil
}

// SetData replace packet data with newData and update payload length in header
func (packet *Packet) SetData(newData []byte) {
	packet.data = newData
	newSize := len(newData)
	packet.updatePacketSize(newSize)
}

// updatePacketSize in header
func (packet *Packet) updatePacketSize(newSize int) {
	// update payload size, first 3 bytes of header
	// https://dev.mysql.com/doc/internals/en/mysql-packet.html#idm140406396409840
	packet.header[0] = byte(newSize)
	packet.header[1] = byte(newSize >> 8)
	packet.header[2] = byte(newSize >> 16)
}

// replaceQuery replace query in payload with new and update header with new size
func (packet *Packet) replaceQuery(newQuery string) {
	if len(newQuery) > len(packet.data[1:]) {
		// first byte CMD + new query
		packet.data = append(packet.data[:1], []byte(newQuery)...)
	} else {
		// if new query less than before then reuse memory of previous query
		n := copy(packet.data[1:], newQuery)
		packet.data = packet.data[:1+n] // CMD + n
	}
	packet.updatePacketSize(len(newQuery) + 1)
}

// readPacket read header to struct and return payload as return result or error
func (packet *Packet) readPacket(connection net.Conn) ([]byte, error) {
	if _, err := io.ReadFull(connection, packet.header); err != nil {
		return nil, err
	}

	length := packet.GetPacketPayloadLength()
	if length < 1 {
		return nil, fmt.Errorf("invalid payload length %d", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(connection, data); err != nil {
		return nil, err
	}
	if length < MaxPayloadLen {
		return data, nil
	}

	var buf []byte
	buf, err := packet.readPacket(connection)
	if err != nil {
		return nil, err
	}
	return append(data, buf...), nil
}

// Dump returns packet header and data as []byte
func (packet *Packet) Dump() []byte {
	return append(packet.header, packet.data...)
}

// ReadPacket header and payload from connection or return error
func (packet *Packet) ReadPacket(connection net.Conn) error {
	data, err := packet.readPacket(connection)
	if err == nil {
		packet.data = data
	}
	return err
}

// IsEOF return true if packet is OkPacket or EOFPacket
func (packet *Packet) IsEOF() bool {
	// https://dev.mysql.com/doc/internals/en/packet-OK_Packet.html
	// https://dev.mysql.com/doc/internals/en/packet-EOF_Packet.html
	isOkPacket := packet.data[0] == OkPacket && packet.GetPacketPayloadLength() > 7
	isEOFPacket := packet.data[0] == EOFPacket && packet.GetPacketPayloadLength() < 9
	return isOkPacket || isEOFPacket
}

// IsErr return true if packet has ErrPacket flag
func (packet *Packet) IsErr() bool {
	return packet.data[0] == ErrPacket
}

func (packet *Packet) getServerCapabilities() int {
	// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#idm140437490034448
	endOfServerVersion := bytes.Index(packet.data[1:], []byte{0}) + 2 // 1 first byte of protocol version and 1 to point to next byte
	// 4 bytes connection string + 8 bytes of auth plugin + 1 byte filler
	rawCapabilities := packet.data[endOfServerVersion+13 : endOfServerVersion+13+2]
	return int(binary.LittleEndian.Uint16(rawCapabilities))
}

func (packet *Packet) getServerCapabilitiesExtended() (int, error) {
	// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#idm140437490034448
	endOfServerVersion := bytes.Index(packet.data[1:], []byte{0}) + 2 // 1 first byte of protocol version and 1 to point to next byte
	// 4 bytes connection string + 8 bytes of auth plugin + 1 byte filler
	baseCapabilitiesOffset := endOfServerVersion + 13
	// 2 bytes of base capabilities + 1 byte character set + 2 bytes of status flags
	capabilitiesOffset := baseCapabilitiesOffset + 2 + 3
	if len(packet.data) < capabilitiesOffset+2 {
		return 0, ErrPacketHasNotExtendedCapabilities
	}
	rawCapabilities := packet.data[capabilitiesOffset : capabilitiesOffset+2]
	return int(binary.LittleEndian.Uint16(rawCapabilities)), nil
}

// ServerSupportProtocol41 if server supports client_protocol_41
func (packet *Packet) ServerSupportProtocol41() bool {
	capabilities := packet.getServerCapabilities()
	return (capabilities & ClientProtocol41) > 0
}

func (packet *Packet) getClientCapabilities() uint32 {
	// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#idm140437489940880
	return binary.LittleEndian.Uint32(packet.data[:4])
}

// ClientSupportProtocol41 if client supports client_protocol_41
func (packet *Packet) ClientSupportProtocol41() bool {
	capabilities := packet.getClientCapabilities()
	return (capabilities & ClientProtocol41) > 0
}

// IsSSLRequest return true if SslRequest flag up
func (packet *Packet) IsSSLRequest() bool {
	capabilities := packet.getClientCapabilities()
	return (capabilities & SslRequest) > 0
}

// IsClientDeprecateEOF return true if flag set
// https://dev.mysql.com/doc/internals/en/capability-flags.html#flag-CLIENT_DEPRECATE_EOF
func (packet *Packet) IsClientDeprecateEOF() bool {
	capabilities := packet.getClientCapabilities()
	return (capabilities & ClientDeprecateEOF) > 0
}

// ReadPacket from connection and return Packet struct with data or error
func ReadPacket(connection net.Conn) (*Packet, error) {
	packet := NewPacket()
	err := packet.ReadPacket(connection)
	if err != nil {
		return nil, err
	}
	return packet, nil
}
