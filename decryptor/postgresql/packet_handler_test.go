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
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/sirupsen/logrus"
	"testing"
)

func TestClientUnknownCommand(t *testing.T) {
	unknownMessageType := byte(1)
	lengthBuf := []byte{0, 0, 0, 7}
	dataBuf := []byte{1, 2, 3}
	packet := bytes.Join([][]byte{{unknownMessageType}, lengthBuf, dataBuf}, []byte{})
	reader := bytes.NewReader(packet)
	output := make([]byte, 8)
	writer := bufio.NewWriter(bytes.NewBuffer(output[:0]))
	packetHander, err := NewClientSidePacketHandler(reader, writer, logrus.NewEntry(logrus.StandardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	if err := packetHander.ReadClientPacket(); err != nil {
		t.Fatal(err)
	}
	if packetHander.messageType[0] != unknownMessageType {
		t.Fatal("Incorrect message type")
	}
	if !bytes.Equal(packetHander.descriptionLengthBuf, lengthBuf) {
		t.Fatal("Incorrect length buf")
	}
	if !bytes.Equal(packetHander.descriptionBuf.Bytes(), dataBuf) {
		t.Fatal("Incorrect data buf")
	}
	if err := packetHander.sendPacket(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output, packet) {
		t.Fatal("Output not equal to correct packet")
	}
}

func TestClientSpecialMessageTypes(t *testing.T) {
	sslLengthBuf := []byte{0, 0, 0, 8}
	cancelRequestLengthBuf := []byte{0, 0, 0, 16}
	lengthBufs := [][]byte{sslLengthBuf, cancelRequestLengthBuf}
	for i, data := range [][]byte{SSLRequest, CancelRequest} {
		packet := bytes.Join([][]byte{lengthBufs[i], data}, []byte{})
		reader := bytes.NewReader(packet)
		output := make([]byte, 8)
		writer := bufio.NewWriter(bytes.NewBuffer(output[:0]))
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
		if !bytes.Equal(packetHander.descriptionLengthBuf, lengthBufs[i]) {
			t.Fatal("Incorrect length buf")
		}
		if !bytes.Equal(packetHander.descriptionBuf.Bytes(), data) {
			t.Fatal("Incorrect data buf")
		}
		if err := packetHander.sendPacket(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(output, packet) {
			t.Fatal("Output not equal to correct packet")
		}
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
	t.Run("Binary data read", func(t *testing.T) {
		testCases := []testCase{
			// valid hex encoded value
			{[]byte("\\xaabb"), []byte("\\xaabb"), []byte("\\xaabb"), 6, base.BinaryFormat},
			// valid octal value
			{[]byte("\\111"), []byte("\\111"), []byte("\\111"), 4, base.BinaryFormat},
			// full binary value
			{[]byte{1, 2, 3}, []byte{1, 2, 3}, []byte{1, 2, 3}, 3, base.BinaryFormat},

			// valid hex encoded value decoded to 2 digits
			{[]byte("\\xaabb"), []byte("\\xaabb"), []byte("\\xaabb"), 6, base.TextFormat},
			// valid hex encoded value decoded to 2 digits
			{[]byte("\\x"), []byte("\\x"), []byte("\\x"), 2, base.TextFormat},
			// valid octal value decoded to 1 digit
			{[]byte("\\001"), []byte("\\001"), []byte("\\001"), 4, base.TextFormat},
			// full binary value that should be as is
			{[]byte{1, 2, 3}, []byte{1, 2, 3}, []byte{1, 2, 3}, 3, base.TextFormat},
		}
		column := &ColumnData{}
		for i, testcase := range testCases {
			binary.BigEndian.PutUint32(column.LengthBuf[:], testcase.columnLength)
			if err := column.readData(bytes.NewReader(testcase.data), testcase.format); err != nil {
				t.Fatal(i, "Error on read data by column", err)
			}
			if !bytes.Equal(column.data, testcase.expected) {
				t.Fatalf("Incorrectly encoded data, %v != %v\n",
					column.data, testcase.expected)
			}
			if !bytes.Equal(column.data, testcase.decoded) {
				t.Fatalf("%d. Decoded data not equal to expected, %s != %s\n", i, column.data, testcase.decoded)
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
	if !bytes.Equal(handler.Columns[0].data, testData) {
		t.Fatal("Incorrect ")
	}
}
