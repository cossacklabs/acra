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
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/keystore/keyloader/env_loader"
	"github.com/cossacklabs/acra/utils/args"
)

func TestRotateSymmetricKey(t *testing.T) {
	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyEnvMasterKey, env_loader.NewEnvKeyEncryptorFabric(keystore.AcraMasterKeyVarName))

	masterKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	dirName := t.TempDir()
	if err := os.Chmod(dirName, 0700); err != nil {
		t.Fatal(err)
	}

	var keyStore keystore.KeyMaking

	flagSet := flag.NewFlagSet(CmdMigrateKeys, flag.ContinueOnError)
	keyloader.RegisterCLIParametersWithFlagSet(flagSet, "", "")

	err = flagSet.Set("keystore_encryption_type", keyloader.KeystoreStrategyEnvMasterKey)
	if err != nil {
		log.Fatal(err)
	}
	extractor := args.NewServiceExtractor(flagSet, map[string]string{})

	clientID := []byte("client")
	generateCmd := &GenerateKeySubcommand{
		CommonKeyStoreParameters: CommonKeyStoreParameters{
			keyDir: dirName,
		},
		clientID:   string(clientID),
		flagSet:    flagSet,
		extractor:  extractor,
		acraBlocks: true,
	}

	keyStore, err = openKeyStoreV1(generateCmd)
	if err != nil {
		t.Fatal(err)
	}

	if err := keyStore.GenerateClientIDSymmetricKey(clientID); err != nil {
		log.WithError(err).Errorln("Can't generate symmetric key")
		os.Exit(1)
	}

	keyPath := fmt.Sprintf("%s/%s_storage_sym", dirName, clientID)
	oldSymKey, err := ioutil.ReadFile(keyPath)
	if err != nil {
		t.Fatal("no old symmetric sym key found")
	}

	generateCmd.Execute()

	newSymKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal("no new symmetric sym key found")
	}

	if bytes.Equal(oldSymKey, newSymKey) {
		t.Fatal("same key after rotation error")
	}

	f, err := os.Open(fmt.Sprintf("%s.old", keyPath))
	if err != nil {
		t.Fatal("no backup directory found", err.Error())
	}
	defer f.Close()

	_, err = f.Readdir(1)
	if err == io.EOF {
		t.Fatal("backup dir is empty")
	}
}
