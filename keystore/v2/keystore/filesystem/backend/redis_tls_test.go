//go:build integration && redis && tls
// +build integration,redis,tls

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
	"crypto/tls"
	"flag"
	"github.com/cossacklabs/acra/cmd"
	tests2 "github.com/cossacklabs/acra/utils/tests"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api/tests"
)

// Tweak these constants if your Redis testing setup is not the default one.
// The tests expect that Redis instance is availble on your machine,
// listening on the default port, with no authentication or TLS.
// This is what you get with "docker run --network=host redis", for example.
//
// Note that the tests do not clean up the database after running, so either
// restart it or delete everything under `testRootDir` before the next run.
const (
	testRootDir = "keystore-v2-test"
)

func prepareTLSRedisConfig(t *testing.T) (cmd.RedisOptions, *flag.FlagSet) {
	flagset := flag.FlagSet{}
	options := cmd.RedisOptions{}
	options.RegisterKeyStoreParameters(&flagset, "", "")
	// set after registering due to setting default value during registration
	hostport := os.Getenv("TEST_REDIS_HOSTPORT")
	if hostport == "" {
		hostport = "localhost:6379"
	}
	password := os.Getenv("TEST_REDIS_PASSWORD")
	if password == "" {
		password = ""
	}
	dbNum := os.Getenv("TEST_REDIS_DB")
	if dbNum == "" {
		dbNum = "0"
	}
	dbInt, err := strconv.ParseInt(dbNum, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	options.DBKeys = int(dbInt)
	workingDirectory := tests2.GetSourceRootDirectory(t)
	if err := flagset.Lookup("redis_tls_client_ca").Value.Set(filepath.Join(workingDirectory, "tests/ssl/ca/ca.crt")); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_tls_client_cert").Value.Set(filepath.Join(workingDirectory, "tests/ssl/acra-client/acra-client.crt")); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_tls_client_key").Value.Set(filepath.Join(workingDirectory, "tests/ssl/acra-client/acra-client.key")); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_tls_client_auth").Value.Set(strconv.FormatUint(uint64(tls.RequireAndVerifyClientCert), 10)); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_tls_client_ocsp_from_cert").Value.Set("ignore"); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_tls_client_crl_from_cert").Value.Set("ignore"); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_host_port").Value.Set(hostport); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_password").Value.Set(password); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_db_keys").Value.Set(dbNum); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_tls_enable").Value.Set("true"); err != nil {
		t.Fatal(err)
	}
	return options, &flagset
}

func TestRedis(t *testing.T) {
	options, flagset := prepareTLSRedisConfig(t)
	redisOptions, err := options.KeysOptions(flagset)
	if err != nil {
		t.Fatal(err)
	}
	tests.TestBackend(t, func(t *testing.T) api.Backend {
		config := &RedisConfig{
			RootDir: testRootDir + "/" + time.Now().Format(time.RFC3339Nano),
			Options: redisOptions,
		}
		backend, err := CreateRedisBackend(config)
		if err != nil {
			t.Fatalf("Failed to create Redis backend: %v", err)
		}
		return backend
	})
}
