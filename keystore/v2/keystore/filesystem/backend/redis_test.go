//go:build integration && redis
// +build integration,redis

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
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api/tests"
	"github.com/go-redis/redis/v7"
)

// Tweak these constants if your Redis testing setup is not the default one.
// The tests expect that Redis instance is availble on your machine,
// listening on the default port, with no authentication or TLS.
// This is what you get with "docker run --network=host redis", for example.
//
// Note that the tests do not clean up the database after running, so either
// restart it or delete everything under `testRootDir` before the next run.
const (
	redisAddress  = "localhost:6379" // TEST_REDIS_HOSTPORT
	redisPassword = ""               // TEST_REDIS_PASSWORD
	redisDatabase = 0                // TEST_REDIS_DB

	testRootDir = "keystore-v2-test"
)

func TestRedis(t *testing.T) {
	tests.TestBackend(t, func(t *testing.T) api.Backend {
		config := &RedisConfig{
			RootDir: testRootDir + "/" + time.Now().Format(time.RFC3339Nano),
			Options: &redis.Options{
				Addr:     redisAddress,
				Password: redisPassword,
				DB:       redisDatabase,
			},
		}
		backend, err := CreateRedisBackend(config)
		if err != nil {
			t.Fatalf("Failed to create Redis backend: %v", err)
		}
		return backend
	})
}

func redisOptions() *redis.Options {
	address := os.Getenv("TEST_REDIS_HOSTPORT")
	if address == "" {
		address = redisAddress
	}
	password := os.Getenv("TEST_REDIS_PASSWORD")
	if password == "" {
		password = redisPassword
	}
	database, err := strconv.Atoi(os.Getenv("TEST_REDIS_DB"))
	if err != nil {
		database = redisDatabase
	}
	return &redis.Options{
		Addr:     address,
		Password: password,
		DB:       database,
	}
}
