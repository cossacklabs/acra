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
	"encoding/hex"
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
