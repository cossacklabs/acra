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
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/keystore/keyloader/env_loader"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/utils/args"
)

func TestPrintKeysDefault(t *testing.T) {
	keys := []keystore.KeyDescription{
		{
			KeyID:   "Another KeyID",
			Purpose: "testing",
		},
	}

	output := strings.Builder{}
	err := keystore.PrintKeysTable(keys, &output)
	if err != nil {
		t.Fatalf("Failed to print keys: %v", err)
	}

	actual := output.String()
	expected := `Index | Key purpose | Client | Key ID
------------+--------+--------------
0     | testing     |        | Another KeyID
`
	if actual != expected {
		t.Errorf("Incorrect output.\nActual:\n%s\nExpected:\n%s", actual, expected)
	}
}

func TestPrintRotatedKeysDefault(t *testing.T) {
	creationTime := time.Unix(1676418028, 0).UTC()
	keys := []keystore.KeyDescription{
		{
			KeyID:        "Another KeyID",
			Purpose:      "testing",
			CreationTime: &creationTime,
		},
	}

	output := strings.Builder{}
	err := keystore.PrintRotatedKeysTable(keys, &output)
	if err != nil {
		t.Fatalf("Failed to print keys: %v", err)
	}

	actual := output.String()
	expected := `
Rotated keys: 
Index | Key purpose | Client | Creation Time                 | Key ID
------------+--------+-------------------------------+-----------
0     | testing     |        | 2023-02-14 23:40:28 +0000 UTC | Another KeyID
`
	if actual != expected {
		t.Errorf("Incorrect output.\nActual:\n%s\nExpected:\n%s", actual, expected)
	}
}

func TestPrintKeysJSON(t *testing.T) {
	keys := []keystore.KeyDescription{
		{
			KeyID:   "Another KeyID",
			Purpose: "testing",
		},
	}

	output := bytes.Buffer{}
	err := printKeysJSON(keys, &output)
	if err != nil {
		t.Fatalf("Failed to print keys: %v", err)
	}

	var actual []keystore.KeyDescription
	err = json.Unmarshal(output.Bytes(), &actual)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON output: %v", err)
	}

	if !equalDescriptionLists(actual, keys) {
		t.Errorf("Incorrect output:\n%s", string(output.Bytes()))
	}
}

func TestListRotatedKeysV1(t *testing.T) {
	clientID := []byte("testclientid")
	timesToRotateKeys := 3
	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyEnvMasterKey, env_loader.NewEnvKeyEncryptorFabric(keystore.AcraMasterKeyVarName))

	masterKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	flagSet := flag.NewFlagSet(CmdMigrateKeys, flag.ContinueOnError)
	keyloader.RegisterCLIParametersWithFlagSet(flagSet, "", "")

	err = flagSet.Set("keystore_encryption_type", keyloader.KeystoreStrategyEnvMasterKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	extractor := args.NewServiceExtractor(flagSet, map[string]string{})

	dirName := t.TempDir()
	if err := os.Chmod(dirName, 0700); err != nil {
		t.Fatal(err)
	}

	listCMD := &ListKeySubcommand{
		CommonKeyStoreParameters: CommonKeyStoreParameters{
			keyDir: dirName,
		},
		CommonKeyListingParameters: CommonKeyListingParameters{
			rotatedKeys: true,
		},
		FlagSet:   flagSet,
		extractor: extractor,
	}

	store, err := openKeyStoreV1(listCMD)
	if err != nil {
		t.Fatal(err)
	}

	if err = store.GenerateDataEncryptionKeys(clientID); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < timesToRotateKeys; i++ {
		if err = store.GenerateDataEncryptionKeys(clientID); err != nil {
			t.Fatal(err)
		}
	}

	pubKeysEntries, err := os.ReadDir(filepath.Join(dirName, string(clientID)+"_storage.pub.old"))
	if err != nil {
		t.Fatal(err)
	}

	pubKeysTimes := make([]time.Time, 0, timesToRotateKeys)
	for _, entry := range pubKeysEntries {
		entryTime, err := time.Parse(filesystem.HistoricalFileNameTimeFormat, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		pubKeysTimes = append(pubKeysTimes, entryTime)
	}

	privateKeysEntries, err := os.ReadDir(filepath.Join(dirName, string(clientID)+"_storage.old"))
	if err != nil {
		t.Fatal(err)
	}

	privateKeysTimes := make([]time.Time, 0, timesToRotateKeys)
	for _, entry := range privateKeysEntries {
		entryTime, err := time.Parse(filesystem.HistoricalFileNameTimeFormat, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		privateKeysTimes = append(privateKeysTimes, entryTime)
	}

	descriptions, err := store.ListRotatedKeys()
	if err != nil {
		t.Fatal(err)
	}

	if len(descriptions) != 2*timesToRotateKeys {
		t.Fatal("Expect exact number of rotated keys description")
	}

	keyIdx := 1
	for i := 0; i < timesToRotateKeys; i++ {
		if descriptions[i].CreationTime.String() != privateKeysTimes[i].String() {
			t.Fatalf("Not expected creation time of rotated private key, %s not equal %s", descriptions[i].CreationTime.String(), privateKeysTimes[i].String())
		}

		if i > 0 {
			if descriptions[i-1].CreationTime.After(*descriptions[i].CreationTime) {
				t.Fatal("Not expected order, expected keys time increased gradually")
			}

			// rotated key index should be greater than 1 and increase in the order
			if descriptions[i-1].Index != keyIdx {
				t.Fatal("Expected key Index greater than 1")
			}
		}

		if descriptions[i+timesToRotateKeys].CreationTime.String() != pubKeysTimes[i].String() {
			t.Fatalf("Not expected creation time of rotated public key, %s not equal %s", descriptions[i].CreationTime.String(), pubKeysTimes[i].String())
		}

		if i > timesToRotateKeys {
			if descriptions[i+timesToRotateKeys-1].CreationTime.After(*descriptions[i+timesToRotateKeys].CreationTime) {
				t.Fatal("Not expected order, expected keys time increased gradually")
			}

			// rotated key index should be greater than 1 and increase in the order
			if descriptions[i+timesToRotateKeys-1].Index != keyIdx+timesToRotateKeys {
				t.Fatal("Expected key Index greater than 1")
			}
		}

		keyIdx++
	}
}

func TestListRotatedKeysJSON(t *testing.T) {
	clientID := []byte("testclientid")
	timesToRotateKeys := 3
	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyEnvMasterKey, env_loader.NewEnvKeyEncryptorFabric(keystore.AcraMasterKeyVarName))

	masterKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	flagSet := flag.NewFlagSet(CmdMigrateKeys, flag.ContinueOnError)
	keyloader.RegisterCLIParametersWithFlagSet(flagSet, "", "")

	err = flagSet.Set("keystore_encryption_type", keyloader.KeystoreStrategyEnvMasterKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))
	extractor := args.NewServiceExtractor(flagSet, map[string]string{})

	dirName := t.TempDir()
	if err := os.Chmod(dirName, 0700); err != nil {
		t.Fatal(err)
	}

	listCMD := &ListKeySubcommand{
		CommonKeyStoreParameters: CommonKeyStoreParameters{
			keyDir: dirName,
		},
		CommonKeyListingParameters: CommonKeyListingParameters{
			rotatedKeys: true,
			useJSON:     true,
		},
		FlagSet:   flagSet,
		extractor: extractor,
	}

	store, err := openKeyStoreV1(listCMD)
	if err != nil {
		t.Fatal(err)
	}

	if err = store.GenerateDataEncryptionKeys(clientID); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < timesToRotateKeys; i++ {
		if err = store.GenerateDataEncryptionKeys(clientID); err != nil {
			t.Fatal(err)
		}
	}

	// overwrite os.Stdout with temp Pipe
	r, w, _ := os.Pipe()
	os.Stdout = w

	ListKeysCommand(listCMD, store)

	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	var result []keystore.KeyDescription
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}

	// expected length: public rotated keys + private rotated keys + current keys
	if len(result) != timesToRotateKeys*2+2 {
		t.Fatal("Not expected number of keys")
	}

	// check current keys
	for i := 0; i < 2; i++ {
		if result[i].State != keystore.StateCurrent {
			t.Fatal("Expect current key in result")
		}

		if result[i].Index != 1 {
			t.Fatal("Invalid key Index in result")
		}
	}

	// check rotated keys
	for i := 2; i < len(result); i++ {
		if result[i].State != keystore.StateRotated {
			t.Fatal("Expect rotated key in result")
		}

		if result[i].Index == 1 {
			t.Fatal("Invalid key Index in result")
		}
	}
}

func TestListRotatedKeysV2(t *testing.T) {
	dirName := t.TempDir()
	if err := os.Chmod(dirName, 0700); err != nil {
		t.Fatal(err)
	}

	timesToRotateKeys := 3
	clientID := []byte("testclientid")

	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyEnvMasterKey, env_loader.NewEnvKeyEncryptorFabric(keystore.AcraMasterKeyVarName))
	masterKey, err := keystoreV2.NewSerializedMasterKeys()
	if err != nil {
		t.Fatal(err)
	}
	flagSet := flag.NewFlagSet(CmdMigrateKeys, flag.ContinueOnError)
	keyloader.RegisterCLIParametersWithFlagSet(flagSet, "", "")

	err = flagSet.Set("keystore_encryption_type", keyloader.KeystoreStrategyEnvMasterKey)
	if err != nil {
		t.Fatal(err)
	}

	extractor := args.NewServiceExtractor(flagSet, map[string]string{})
	t.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	listCMD := &ListKeySubcommand{
		CommonKeyStoreParameters: CommonKeyStoreParameters{
			keyDir: dirName,
		},
		CommonKeyListingParameters: CommonKeyListingParameters{
			rotatedKeys: true,
		},
		FlagSet:   flagSet,
		extractor: extractor,
	}

	store, err := openKeyStoreV2(listCMD)
	if err != nil {
		t.Fatal(err)
	}

	if err = store.GenerateDataEncryptionKeys(clientID); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < timesToRotateKeys; i++ {
		if err = store.GenerateDataEncryptionKeys(clientID); err != nil {
			t.Fatal(err)
		}
		// sleep to have different rotated time
		time.Sleep(time.Second)
	}

	descriptions, err := store.ListRotatedKeys()
	if err != nil {
		t.Fatal(err)
	}

	if len(descriptions) != timesToRotateKeys {
		t.Fatal("Expect exact number of historical keys description")
	}

	keyIdx := 1
	for i := 0; i < len(descriptions); i++ {
		if i > 0 {
			if descriptions[i-1].CreationTime.After(*descriptions[i].CreationTime) {
				t.Fatal("Not expected order, expected keys time increased gradually")
			}

			// rotated key index should be greater than 1 and increase in order
			if descriptions[i-1].Index != keyIdx {
				t.Fatal("Expected key Index greater than 1")
			}
		}
		keyIdx++
	}
}

func equalDescriptionLists(a, b []keystore.KeyDescription) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !equalDescriptions(a[i], b[i]) {
			return false
		}
	}
	return true
}

func equalDescriptions(a, b keystore.KeyDescription) bool {
	return a.KeyID == b.KeyID && a.Purpose == b.Purpose && bytes.Equal([]byte(a.ClientID), []byte(b.ClientID)) && a.Index == b.Index
}
