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

package filesystem

import (
	"fmt"
	"sync"
)

var lock = sync.RWMutex{}

const (
	POISON_KEY_FILENAME     = ".poison_key/poison_key"
	BASIC_AUTH_KEY_FILENAME = "auth_key"
)

func getZoneKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_zone", string(id))
}

func getPublicKeyFilename(id []byte) string {
	return fmt.Sprintf("%s.pub", id)
}

func getZonePublicKeyFilename(id []byte) string {
	return getPublicKeyFilename([]byte(getZoneKeyFilename(id)))
}

func getServerKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_server", string(id))
}

func getTranslatorKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_translator", string(id))
}

func getServerDecryptionKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_storage", string(id))
}

func getConnectorKeyFilename(id []byte) string {
	return string(id)
}
