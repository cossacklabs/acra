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
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/sirupsen/logrus"
)

func TestClientOneLetterCommands(t *testing.T) {
	ids := []byte{'B', 'C', 'd', 'c', 'f', 'D', 'E', 'H', 'F', 'p', 'P', 'Q', 'S', 'X'}

	for _, id := range ids {
		len := []byte{0x00, 0x00, 0x00, 0x08}
		randomPayload := []byte{0x48, 0xfc, 0xbf, 0xc3}

		// Message which consists of:
		// id + 4-byte size of a packet (without id) + something random
		packet := bytes.Join([][]byte{{id}, len, randomPayload}, []byte{})
		reader := bytes.NewReader(packet)
		output := make([]byte, 8)
		writer := bufio.NewWriter(bytes.NewBuffer(output[:0]))
		packetHander, err := NewClientSidePacketHandler(reader, writer, logrus.NewEntry(logrus.StandardLogger()))
		// Test as if one of the startup messages is received
		packetHander.started = true
		if err != nil {
			t.Fatal(err)
		}
		if err := packetHander.ReadClientPacket(); err != nil {
			t.Fatal(err)
		}
		if packetHander.messageType[0] != id {
			t.Fatalf("wrong messageType: expected %x, but found %x", id, packetHander.messageType[0])
		}
		// length doesn't include "length" itself
		if packetHander.dataLength != 4 {
			t.Fatalf("wrong dataLength: expected 4, but found %x", packetHander.dataLength)
		}

		if !bytes.Equal(packetHander.descriptionLengthBuf, len) {
			t.Fatalf("Incorrect length buf: expected %x, but found %x", len, packetHander.descriptionLengthBuf)
		}
	}
}

func TestClientStartupMessagePackets(t *testing.T) {
	packets := [][]byte{
		// SSLRequest:
		// - 4-byte length (8 bytes)
		// - 4-byte magic num
		{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f},

		// CancelRequest:
		// - 4-byte length (16 bytes)
		// - 4-byte magic num
		// - 4-byte processId
		// - 4-byte secrekey
		{0x00, 0x00, 0x00, 0x10, 0x04, 0xd2, 0x16, 0x2e, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb},

		// StartupRequest
		// - 4-byte length (in this case 10 bytes)
		// - 4-byte magic num
		// - variable size payload
		{0x00, 0x00, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},

		// GSSENCRequest
		// - 4-byte length (8 bytes)
		// - 4-byte magic num
		{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x30},
	}

	for _, packet := range packets {
		reader := bytes.NewReader(packet)
		output := make([]byte, 16)
		writer := bufio.NewWriter(bytes.NewBuffer(output[:0]))
		packetHander, err := NewClientSidePacketHandler(reader, writer, logrus.NewEntry(logrus.StandardLogger()))
		if err != nil {
			t.Fatal(err)
		}
		if err := packetHander.ReadClientPacket(); err != nil {
			t.Fatal(err)
		}

		if err := packetHander.sendPacket(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestClientUnknownCommand(t *testing.T) {
	unknownMessageType := byte(1)
	lengthBuf := []byte{0, 0, 0, 7}
	dataBuf := []byte{1, 2, 3}
	packet := bytes.Join([][]byte{{unknownMessageType}, lengthBuf, dataBuf}, []byte{})
	reader := bytes.NewReader(packet)
	output := make([]byte, 8)
	writer := bufio.NewWriter(bytes.NewBuffer(output[:0]))
	packetHander, err := NewClientSidePacketHandler(reader, writer, logrus.NewEntry(logrus.StandardLogger()))
	// Test as if one of the startup messages is received
	packetHander.started = true
	if err != nil {
		t.Fatal(err)
	}
	if err := packetHander.ReadClientPacket(); err != nil {
		t.Fatal(err)
	}
}

func TestClientStartupMessageWithData(t *testing.T) {
	// took some startup auth message with wireshark
	packet, err := hex.DecodeString("0000004c000300007573657200746573740064617461626173650074657374006170706c69636174696f6e5f6e616d65007073716c00636c69656e745f656e636f64696e6700555446380000")
	if err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(packet)
	output := &bytes.Buffer{}
	writer := bufio.NewWriter(output)
	packetHander, err := NewClientSidePacketHandler(reader, writer, logrus.NewEntry(logrus.StandardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	if err := packetHander.ReadClientPacket(); err != nil {
		t.Fatal(err)
	}
	if packetHander.messageType[0] != WithoutMessageType {
		t.Fatal("Incorrect message type")
	}
	if err := packetHander.sendPacket(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), packet) {
		t.Fatal("Output not equal to correct packet")
	}
}

func TestColumnData_readData(t *testing.T) {
	type testCase struct {
		data         []byte
		decoded      []byte
		expected     []byte
		columnLength uint32
		format       base.BoundValueFormat
	}
	t.Run("Binary encoding", func(t *testing.T) {
		testCases := []testCase{
			// valid hex encoded value
			{[]byte("\\xaabb"), []byte("\\xaabb"), []byte("\\xaabb"), 6, base.BinaryFormat},
			// valid octal value
			{[]byte("\\111"), []byte("\\111"), []byte("\\111"), 4, base.BinaryFormat},
			// full binary value
			{[]byte{1, 2, 3}, []byte{1, 2, 3}, []byte{1, 2, 3}, 3, base.BinaryFormat},

			// valid hex encoded value decoded to 2 digits
			{[]byte("\\xaabb"), []byte{170, 187}, []byte("\\xaabb"), 6, base.TextFormat},
			// valid hex encoded value decoded to 2 digits
			{[]byte("\\x"), []byte{}, []byte("\\x"), 2, base.TextFormat},
			// valid octal value decoded to 1 digit
			{[]byte("\\001"), []byte{1}, []byte("\\001"), 4, base.TextFormat},
			// full binary value that should be as is
			{[]byte{1, 2, 3}, []byte{1, 2, 3}, []byte{1, 2, 3}, 3, base.TextFormat},
		}
		column := &ColumnData{}
		for i, testcase := range testCases {
			binary.BigEndian.PutUint32(column.LengthBuf[:], testcase.columnLength)
			if err := column.readData(bytes.NewReader(testcase.data), testcase.format); err != nil {
				t.Fatal(i, "Error on read data by column", err)
			}
			if !bytes.Equal(column.data.Encoded(), testcase.expected) {
				t.Fatalf("Incorrectly encoded data, %v != %v\n",
					column.data.Encoded(), testcase.expected)
			}
			if !bytes.Equal(column.data.Data(), testcase.decoded) {
				t.Fatalf("Decoded data not equal to expected, %s != %s\n", column.data.Data(), testcase.decoded)
			}
		}
	})
}

func TestParseColumns(t *testing.T) {
	buffer := make([]byte, 10)
	// column count, 2 bytes field, 1 column
	binary.BigEndian.PutUint16(buffer[:2], 1)
	// column length, 4 bytes field, 4 bytes length of column
	binary.BigEndian.PutUint32(buffer[2:6], 4)
	// column length, 4 bytes value of "\111"
	testData := []byte("\\111")
	copy(buffer[6:], testData)

	handler := &PacketHandler{descriptionBuf: bytes.NewBuffer(buffer), logger: logrus.NewEntry(logrus.New())}
	if err := handler.parseColumns([]uint16{uint16(base.BinaryFormat)}); err != nil {
		t.Fatal(err)
	}
	if len(handler.Columns) != 1 {
		t.Fatal("Incorrect length of columns")
	}
	if !bytes.Equal(handler.Columns[0].data.Encoded(), testData) {
		t.Fatal("Incorrect ")
	}
}
