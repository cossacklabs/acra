//go:build integration && redis
// +build integration,redis

/*
Copyright 2020, Cossack Labs Limited

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

package keys

import (
	"encoding/base64"
	"io/ioutil"
	"os"
	"testing"

	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/pseudonymization/storage"
)

func TestReadCMD_Redis_V2(t *testing.T) {
	client, err := storage.NewRedisClient("127.0.0.1:6379", "", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.FlushAll()

	clientID := []byte("testclientid")
	keyLoader := keyloader.NewEnvLoader(keystore.AcraMasterKeyVarName)

	masterKey, err := keystoreV2.NewSerializedMasterKeys()
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	readCmd := &ReadKeySubcommand{
		CommonKeyStoreParameters: CommonKeyStoreParameters{
			redisOptions: cmd.RedisOptions{
				HostPort: "127.0.0.1:6379",
			},
		},
		contextID:   clientID,
		readKeyKind: KeyStoragePublic,
	}

	store, err := openKeyStoreV2(readCmd, keyLoader)
	if err != nil {
		t.Fatal(err)
	}

	err = store.GenerateDataEncryptionKeys(clientID)
	if err != nil {
		t.Fatal(err)
	}

	readCmd.Execute()
}

func TestReadCMD_Redis_V1(t *testing.T) {
	client, err := storage.NewRedisClient("127.0.0.1:6379", "", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.FlushAll()

	clientID := []byte("testclientid")
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

	readCmd := &ReadKeySubcommand{
		CommonKeyStoreParameters: CommonKeyStoreParameters{
			redisOptions: cmd.RedisOptions{
				HostPort: "127.0.0.1:6379",
			},
			keyDir: dirName,
		},
		contextID:   clientID,
		readKeyKind: KeyStoragePublic,
	}

	store, err := openKeyStoreV1(readCmd, keyLoader)
	if err != nil {
		t.Fatal(err)
	}

	err = store.GenerateDataEncryptionKeys(clientID)
	if err != nil {
		t.Fatal(err)
	}

	readCmd.Execute()
}
