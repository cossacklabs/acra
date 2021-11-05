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

package grpc_api

import (
	storage2 "github.com/cossacklabs/acra/pseudonymization/storage"
	"testing"
)

func TestTranslator_serviceRedis(t *testing.T) {
	client, err := storage2.NewRedisClient("127.0.0.1:6379", "", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := storage2.NewRedisStorage(client)
	if err != nil {
		t.Fatal(err)
	}
	testTranslatorService(storage, t)
}
