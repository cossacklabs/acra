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
	"fmt"
	"io"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
)

// PrintKeys prints key list prettily into the given writer.
func PrintKeys(keys []keystore.KeyDescription, writer io.Writer, params *CommandLineParams) error {
	return printKeysTable(keys, writer)
}

const (
	purposeHeader = "Key purpose"
	extraIDHeader = "Client/Zone ID"
	idHeader      = "Key ID"
)

func printKeysTable(keys []keystore.KeyDescription, writer io.Writer) error {
	maxPurposeLen := len(purposeHeader)
	maxExtraIDLen := len(extraIDHeader)
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
	}

	fmt.Fprintf(writer, "%-*s  %-*s  %s\n", maxPurposeLen, purposeHeader, maxExtraIDLen, extraIDHeader, idHeader)

	separator := make([]byte, maxPurposeLen+maxExtraIDLen+len(idHeader)+4)
	utils.FillSlice(byte('-'), separator)
	fmt.Fprintln(writer, string(separator))

	for _, key := range keys {
		var extraID string
		if key.ClientID != nil {
			extraID = string(key.ClientID)
		}
		if key.ZoneID != nil {
			extraID = string(key.ZoneID)
		}
		fmt.Fprintf(writer, "%*s  %*s  %s\n", maxPurposeLen, key.Purpose, maxExtraIDLen, extraID, key.ID)
	}
	return nil
}
