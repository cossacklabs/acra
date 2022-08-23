//go:build integration && redis && tls
// +build integration,redis,tls

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

package grpc_api

import (
	storage2 "github.com/cossacklabs/acra/pseudonymization/storage"
	"os"
	"strconv"
	"testing"
)

func TestTranslator_serviceTLSRedis(t *testing.T) {
	redisClientTLS := newClientTLSConfig(t)
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
	client, err := storage2.NewRedisClient(hostport, password, int(dbInt), redisClientTLS)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := storage2.NewRedisStorage(client)
	if err != nil {
		t.Fatal(err)
	}
	testTranslatorService(storage, t)
}
