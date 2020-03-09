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

package backend

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api/tests"
)

func TestFilesystem(t *testing.T) {
	testDirs := make([]string, 0)
	tests.TestBackend(t, func(t *testing.T) api.Backend {
		testRootDir, err := ioutil.TempDir(os.TempDir(), "fs-tests")
		if err != nil {
			t.Fatalf("failed to create tempdir: %v", err)
		}
		testDirs = append(testDirs, testRootDir)
		backend, err := CreateDirectoryBackend(testRootDir)
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}
		return backend
	})
	defer func() {
		for _, dir := range testDirs {
			os.RemoveAll(dir)
		}
	}()
}
