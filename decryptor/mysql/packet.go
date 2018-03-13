package mysql

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	// CLIENT_PROTOCOL_41 - https://dev.mysql.com/doc/internals/en/capability-flags.html#flag-CLIENT_PROTOCOL_41
	CLIENT_PROTOCOL_41 = 0x00000200
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

const (
	// OK_PACKET - https://dev.mysql.com/doc/internals/en/packet-OK_Packet.html
	OK_PACKET = 0x00
	// EOF_PACKET - https://dev.mysql.com/doc/internals/en/packet-EOF_Packet.html
	EOF_PACKET = 0xfe
	ERR_PACKET = 0xff
)

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

func (packet *MysqlPacket) SupportProtocol41() bool {
	capabilities := int(binary.LittleEndian.Uint16(packet.data[:2]))
	return (capabilities & CLIENT_PROTOCOL_41) == 1
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
