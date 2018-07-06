package mysql

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	// CLIENT_PROTOCOL_41 - https://dev.mysql.com/doc/internals/en/capability-flags.html#flag-CLIENT_PROTOCOL_41
	CLIENT_PROTOCOL_41 = 0x00000200
	// SSL_REQUEST - https://dev.mysql.com/doc/internals/en/capability-flags.html#flag-CLIENT_SSL
	SSL_REQUEST = 0x00000800
	// https://dev.mysql.com/doc/internals/en/capability-flags.html#flag-CLIENT_DEPRECATE_EOF - 0x1000000
	CLIENT_DEPRECATE_EOF = 0x01000000
)

const (
	// OK_PACKET - https://dev.mysql.com/doc/internals/en/packet-OK_Packet.html
	OK_PACKET = 0x00
	// EOF_PACKET - https://dev.mysql.com/doc/internals/en/packet-EOF_Packet.html
	EOF_PACKET = 0xfe
	ERR_PACKET = 0xff
)

const (
	// PACKET_HEADER_SIZE https://dev.mysql.com/doc/internals/en/mysql-packet.html#idm140406396409840
	PACKET_HEADER_SIZE = 4
	// SEQUENCE_ID_INDEX last byte of header https://dev.mysql.com/doc/internals/en/mysql-packet.html#idm140406396409840
	SEQUENCE_ID_INDEX = 3
)

var ErrPacketHasNotExtendedCapabilities = errors.New("packet hasn't extended capabilities")

type Dumper interface {
	Dump() []byte
}

type ByteArrayDump []byte

func (array ByteArrayDump) Dump() []byte {
	return array
}

// MysqlPacket struct that store header and payload, read it from connectino
type MysqlPacket struct {
	header []byte
	data   []byte
}

// NewMysqlPacket
func NewMysqlPacket() *MysqlPacket {
	// https://dev.mysql.com/doc/internals/en/mysql-packet.html#idm140406396409840
	// 3 bytes payload length and 1 byte of sequence_id
	return &MysqlPacket{header: make([]byte, PACKET_HEADER_SIZE)}
}

// GetPacketPayloadLength
func (packet *MysqlPacket) GetPacketPayloadLength() int {
	// first 3 bytes of header
	// https://dev.mysql.com/doc/internals/en/mysql-packet.html#idm140406396409840
	return int(uint32(packet.header[0]) | uint32(packet.header[1])<<8 | uint32(packet.header[2])<<16)
}

// GetSequenceNumber return as byte
func (packet *MysqlPacket) GetSequenceNumber() byte {
	return packet.header[SEQUENCE_ID_INDEX]
}

// GetData return packet payload
func (packet *MysqlPacket) GetData() []byte {
	return packet.data
}

// SetData replace packet data with newData and update payload length in header
func (packet *MysqlPacket) SetData(newData []byte) {
	packet.data = newData
	newSize := len(newData)
	// update payload size, first 3 bytes of header
	// https://dev.mysql.com/doc/internals/en/mysql-packet.html#idm140406396409840
	packet.header[0] = byte(newSize)
	packet.header[1] = byte(newSize >> 8)
	packet.header[2] = byte(newSize >> 16)
}

// readPacket read header to struct and return payload as return result or error
func (packet *MysqlPacket) readPacket(connection net.Conn) ([]byte, error) {
	if _, err := connection.Read(packet.header); err != nil {
		return nil, err
	}

	length := packet.GetPacketPayloadLength()
	if length < 1 {
		return nil, fmt.Errorf("invalid payload length %d", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(connection, data); err != nil {
		return nil, err
	} else {
		if length < MaxPayloadLen {
			return data, nil
		}

		var buf []byte
		buf, err = packet.readPacket(connection)
		if err != nil {
			return nil, err
		} else {
			return append(data, buf...), nil
		}
	}
}
func (packet *MysqlPacket) Dump() []byte {
	return append(packet.header, packet.data...)
}

// ReadPacket header and payload from connection or return error
func (packet *MysqlPacket) ReadPacket(connection net.Conn) error {
	data, err := packet.readPacket(connection)
	if err == nil {
		packet.data = data
	}
	return err
}

// IsEOF return true if packet is OK_PACKET or EOF_PACHET
func (packet *MysqlPacket) IsEOF() bool {
	// https://dev.mysql.com/doc/internals/en/packet-OK_Packet.html
	// https://dev.mysql.com/doc/internals/en/packet-EOF_Packet.html
	isOkPacket := packet.data[0] == OK_PACKET && packet.GetPacketPayloadLength() > 7
	isEOFPacket := packet.data[0] == EOF_PACKET && packet.GetPacketPayloadLength() < 9
	return isOkPacket || isEOFPacket
}

// IsErr return true if packet has ERR_PACKET flag
func (packet *MysqlPacket) IsErr() bool {
	return packet.data[0] == ERR_PACKET
}

func (packet *MysqlPacket) getServerCapabilities() int {
	// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#idm140437490034448
	endOfServerVersion := bytes.Index(packet.data[1:], []byte{0}) + 2 // 1 first byte of protocol version and 1 to point to next byte
	// 4 bytes connection string + 8 bytes of auth plugin + 1 byte filler
	rawCapabilities := packet.data[endOfServerVersion+13 : endOfServerVersion+13+2]
	return int(binary.LittleEndian.Uint16(rawCapabilities))
}

func (packet *MysqlPacket) getServerCapabilitiesExtended() (int, error) {
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

func (packet *MysqlPacket) ServerSupportProtocol41() bool {
	capabilities := packet.getServerCapabilities()
	return (capabilities & CLIENT_PROTOCOL_41) > 0
}

func (packet *MysqlPacket) getClientCapabilities() uint32 {
	// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#idm140437489940880
	return binary.LittleEndian.Uint32(packet.data[:4])
}

func (packet *MysqlPacket) ClientSupportProtocol41() bool {
	capabilities := packet.getClientCapabilities()
	return (capabilities & CLIENT_PROTOCOL_41) > 0
}

// IsSSLRequest return true if SSL_REQUEST flag up
func (packet *MysqlPacket) IsSSLRequest() bool {
	capabilities := packet.getClientCapabilities()
	return (capabilities & SSL_REQUEST) > 0
}

// IsClientDeprecatedEOF return true if flag set
// https://dev.mysql.com/doc/internals/en/capability-flags.html#flag-CLIENT_DEPRECATE_EOF
func (packet *MysqlPacket) IsClientDeprecateEOF() bool {
	capabilities := packet.getClientCapabilities()
	return (capabilities & CLIENT_DEPRECATE_EOF) > 0
}

// ReadPacket from connection and return MysqlPacket struct with data or error
func ReadPacket(connection net.Conn) (*MysqlPacket, error) {
	packet := NewMysqlPacket()
	err := packet.ReadPacket(connection)
	if err != nil {
		return nil, err
	}
	return packet, nil
}
