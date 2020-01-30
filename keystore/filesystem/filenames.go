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

package filesystem

import (
	"fmt"
)

// Default key folders' filenames
const (
	PoisonKeyFilename    = ".poison_key/poison_key"
	BasicAuthKeyFilename = "auth_key"
)

// getZoneKeyFilename
func getZoneKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_zone", string(id))
}

// getPublicKeyFilename
func getPublicKeyFilename(id []byte) string {
	return fmt.Sprintf("%s.pub", id)
}

// getZonePublicKeyFilename
func getZonePublicKeyFilename(id []byte) string {
	return getPublicKeyFilename([]byte(getZoneKeyFilename(id)))
}

// getServerKeyFilename
func getServerKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_server", string(id))
}

// getTranslatorKeyFilename
func getTranslatorKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_translator", string(id))
}

// GetServerDecryptionKeyFilename return filename for decryption key
func GetServerDecryptionKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_storage", string(id))
}

// getConnectorKeyFilename
func getConnectorKeyFilename(id []byte) string {
	return string(id)
}
