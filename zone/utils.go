// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package zone

import (
	"encoding/base64"
	"encoding/json"
	"github.com/cossacklabs/themis/gothemis/keys"
)

func ZoneDataToJson(id []byte, public_key *keys.PublicKey) ([]byte, error) {
	response := make(map[string]string)
	response["id"] = string(id)
	response["public_key"] = base64.StdEncoding.EncodeToString(public_key.Value)
	json_output, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	return json_output, nil
}
