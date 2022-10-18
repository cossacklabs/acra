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
	"encoding/hex"
	"testing"
)

// parsePacketQuery contain query that used in parsePacketHex
// took from wireshark
var parsePacketQuery = "Select 1 from test where data=$1"
var parsePacketHex = "5000000029310053656c65637420312066726f6d207465737420776865726520646174613d2431000000"

func TestFetchQueryFromParse(t *testing.T) {
	parsePacket, err := hex.DecodeString(parsePacketHex)
	if err != nil {
		t.Fatal(err)
	}
	query, err := FetchQueryFromParse(parsePacket[5:])
	if err != nil {
		t.Fatal(err)
	}
	if len(query) != len(parsePacketQuery)+1 {
		t.Fatal("Incorrect query length")
	}
	if string(query[:len(query)-1]) != parsePacketQuery {
		t.Fatal("Incorrect query string")
	}
}

func TestParseCommand(t *testing.T) {
	// copied from wireshark and java app with data which found that error
	parseHexWithParameters := `500000009e00696e7365727420696e746f20626c6f675f656e747269657328617574686f722c20626f64792c20626f64795f68746d6c2c20686561646c696e652c2073756d6d6172792c2073756d6d6172795f68746d6c2c206964292076616c756573202824312c2024322c2024332c2024342c2024352c2024362c2024372900000700000011000000110000001100000011000000110000001100000017`
	parseBin, err := hex.DecodeString(parseHexWithParameters)
	if err != nil {
		t.Fatal(err)
	}
	const headerLength = 5
	parseBin = parseBin[headerLength:]

	packet, err := NewParsePacket(parseBin)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parseBin, packet.Marshal()) {
		t.Fatal("parsed and marshaled data not equal")
	}
}

func TestWriteParameterArrayEmptyString(t *testing.T) {
	buffer := bytes.Buffer{}
	bindValue, err := hex.DecodeString(`0000000100000001000000000000`)
	if err != nil {
		t.Fatal(err)
	}
	bindPacket, err := NewBindPacket(bindValue)
	if err != nil {
		t.Fatal(err)
	}
	length, err := writeParameterArray(&buffer, bindPacket.paramValues)
	if err != nil {
		t.Fatal(err)
	}
	if length != 6 {
		t.Fatal(err)
	}
	// 1 parameter
	if !bytes.Equal(buffer.Bytes()[:2], []byte{0, 1}) {
		t.Fatal("Unexpected length of parameters")
	}

	// one parameter with empty string
	if !bytes.Equal(buffer.Bytes()[2:], []byte{0, 0, 0, 0}) {
		t.Fatal("Empty")
	}
}

func TestWriteParameterArrayNullValue(t *testing.T) {
	buffer := bytes.Buffer{}
	bindValue, err := hex.DecodeString(`0000000100000001ffffffff0000`)
	if err != nil {
		t.Fatal(err)
	}
	bindPacket, err := NewBindPacket(bindValue)
	if err != nil {
		t.Fatal(err)
	}
	length, err := writeParameterArray(&buffer, bindPacket.paramValues)
	if err != nil {
		t.Fatal(err)
	}
	if length != 6 {
		t.Fatal(err)
	}
	// 1 parameter
	if !bytes.Equal(buffer.Bytes()[:2], []byte{0, 1}) {
		t.Fatal("Unexpected length of parameters")
	}

	// one parameter with null value as -1 or 0xffffffff
	if !bytes.Equal(buffer.Bytes()[2:], []byte{255, 255, 255, 255}) {
		t.Fatal("Empty")
	}
}
