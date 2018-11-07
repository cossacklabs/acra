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
