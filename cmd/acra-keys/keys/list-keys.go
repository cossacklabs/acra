/*
 * Copyright 2020, Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package keys

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
)

// ListKeysParams ara parameters of "acra-keys list" subcommand.
type ListKeysParams interface {
	UseJSON() bool
}

// PrintKeys prints key list prettily into the given writer.
func PrintKeys(keys []keystore.KeyDescription, writer io.Writer, params ListKeysParams) error {
	if params.UseJSON() {
		return printKeysJSON(keys, writer)
	}
	return printKeysTable(keys, writer)
}

func printKeysJSON(keys []keystore.KeyDescription, writer io.Writer) error {
	json, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	json = append(json, byte('\n'))
	_, err = writer.Write(json)
	return err
}

const (
	purposeHeader = "Key purpose"
	extraIDHeader = "Client/Zone ID"
	idHeader      = "Key ID"
)

func printKeysTable(keys []keystore.KeyDescription, writer io.Writer) error {
	maxPurposeLen := len(purposeHeader)
	maxExtraIDLen := len(extraIDHeader)
	maxKeyIDLen := len(idHeader)
	for _, key := range keys {
		if len(key.Purpose) > maxPurposeLen {
			maxPurposeLen = len(key.Purpose)
		}
		if len(key.ClientID) > maxExtraIDLen {
			maxExtraIDLen = len(key.ClientID)
		}
		if len(key.ZoneID) > maxExtraIDLen {
			maxExtraIDLen = len(key.ZoneID)
		}
		if len(key.ID) > maxKeyIDLen {
			maxKeyIDLen = len(key.ID)
		}
	}

	fmt.Fprintf(writer, "%-*s | %-*s | %s\n", maxPurposeLen, purposeHeader, maxExtraIDLen, extraIDHeader, idHeader)

	separator := make([]byte, maxPurposeLen+maxExtraIDLen+maxKeyIDLen+6)
	utils.FillSlice(byte('-'), separator)
	separator[maxPurposeLen+1] = byte('+')
	separator[maxPurposeLen+maxExtraIDLen+4] = byte('+')
	fmt.Fprintln(writer, string(separator))

	for _, key := range keys {
		var extraID string
		if key.ClientID != nil {
			extraID = string(key.ClientID)
		}
		if key.ZoneID != nil {
			extraID = string(key.ZoneID)
		}
		fmt.Fprintf(writer, "%-*s | %-*s | %s\n", maxPurposeLen, key.Purpose, maxExtraIDLen, extraID, key.ID)
	}
	return nil
}
