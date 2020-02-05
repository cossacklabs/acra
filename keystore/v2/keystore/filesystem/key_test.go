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

package filesystem

import (
	"testing"

	"github.com/cossacklabs/acra/keystore/v2/keystore/api/tests"
)

func TestKeyInMemory(t *testing.T) {
	tests.TestKey(t, newInMemoryKeyStore)
}

func TestKeyFilesystem(t *testing.T) {
	newFilesystemKeyStore, cleanup := testFilesystemKeyStore(t)
	defer cleanup()
	tests.TestKey(t, newFilesystemKeyStore)
}
