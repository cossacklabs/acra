/*
Copyright 2018, Cossack Labs Limited

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

// Package common has shared data betwee gRPC API handler and HTTP API handler.
package common

import (
	"errors"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
)

// TranslatorData connects KeyStorage and Poison records settings for HTTP and gRPC decryptors.
type TranslatorData struct {
	Keystorage            keystore.MultiKeyStore
	PoisonRecordCallbacks *base.PoisonCallbackStorage
	CheckPoisonRecords    bool
}

var (
	// ErrEmptyClientAndZoneID errors for case when wasn't provided clientID and zoneID in api call
	ErrEmptyClientAndZoneID = errors.New("empty clientID and zoneID")
)
