package mysql

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	// CLIENT_PROTOCOL_41 - https://dev.mysql.com/doc/internals/en/capability-flags.html#flag-CLIENT_PROTOCOL_41
	CLIENT_PROTOCOL_41 = 0x00000200
)

const (
	// OK_PACKET - https://dev.mysql.com/doc/internals/en/packet-OK_Packet.html
	OK_PACKET = 0x00
	// EOF_PACKET - https://dev.mysql.com/doc/internals/en/packet-EOF_Packet.html
	EOF_PACKET = 0xfe
	ERR_PACKET = 0xff
)

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
	return &MysqlPacket{header: make([]byte, 4)}
}

// GetPacketPayloadLength
func (packet *MysqlPacket) GetPacketPayloadLength() int {
	return int(uint32(packet.header[0]) | uint32(packet.header[1])<<8 | uint32(packet.header[2])<<16)
}

// GetSequenceNumber return as byte
func (packet *MysqlPacket) GetSequenceNumber() byte {
	return packet.header[3]
}

// GetData return packet payload
func (packet *MysqlPacket) GetData() []byte {
	return packet.data
}

// SetData replace packet data with newData and update payload length in header
func (packet *MysqlPacket) SetData(newData []byte) {
	packet.data = newData
	newSize := len(newData)
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

func (packet *MysqlPacket) IsErr() bool {
	return packet.data[0] == ERR_PACKET
}

func (packet *MysqlPacket) getServerCapabilitiesFromGreeting(data []byte) uint16 {
	endOfServerVersion := bytes.Index(data[1:], []byte{0}) + 2 // 1 first byte of protocol version and 1 to point to next byte
	// 4 bytes connection string + 8 bytes of auth plugin + 1 byte filler
	capabilities := data[endOfServerVersion+13 : endOfServerVersion+13+2]
	return binary.LittleEndian.Uint16(capabilities)
}

func (packet *MysqlPacket) SupportProtocol41() bool {
	capabilities := int(packet.getServerCapabilitiesFromGreeting(packet.data))
	return (capabilities & CLIENT_PROTOCOL_41) > 0
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
