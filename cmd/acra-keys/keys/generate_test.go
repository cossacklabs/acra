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
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/keyloader"
	log "github.com/sirupsen/logrus"
)

func TestRotateSymmetricZoneKey(t *testing.T) {
	zoneID := "DDDDDDDDHCzqZAZNbBvybWLR"
	keyLoader := keyloader.NewEnvLoader(keystore.AcraMasterKeyVarName)

	masterKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	dirName, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dirName)

	var keyStore keystore.KeyMaking

	generateCmd := &GenerateKeySubcommand{
		CommonKeyStoreParameters: CommonKeyStoreParameters{
			keyDir: dirName,
			keyLoaderOptions: keyloader.CLIOptions{
				KeystoreEncryptorType: keyloader.KeystoreStrategyMasterKey,
			},
		},
		zoneID:        zoneID,
		rotateZoneSym: true,
	}

	keyStore, err = openKeyStoreV1(generateCmd, keyLoader)
	if err != nil {
		t.Fatal(err)
	}

	if err := keyStore.GenerateZoneIDSymmetricKey([]byte(zoneID)); err != nil {
		log.WithError(err).Errorln("Can't generate symmetric key")
		os.Exit(1)
	}

	zoneKeyPath := fmt.Sprintf("%s/%s_zone_sym", dirName, zoneID)
	oldSymKey, err := ioutil.ReadFile(zoneKeyPath)
	if err != nil {
		t.Fatal("no old symmetric zone key found")
	}

	generateCmd.Execute()

	newSymKey, err := ioutil.ReadFile(zoneKeyPath)
	if err != nil {
		t.Fatal("no new symmetric zone key found")
	}

	if bytes.Equal(oldSymKey, newSymKey) {
		t.Fatal("same key after rotation error")
	}

	f, err := os.Open(fmt.Sprintf("%s.old", zoneKeyPath))
	if err != nil {
		t.Fatal("no backup directory found", err.Error())
	}
	defer f.Close()

	_, err = f.Readdir(1)
	if err == io.EOF {
		t.Fatal("backup dir is empty")
	}
}
