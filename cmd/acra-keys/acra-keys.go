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

// Package main is entry point for `acra-keys` utility.
//
// It can access and maniplulate key stores:
//
//   - read key data
//   - destroy keys
package main

import (
	"os"

	"github.com/cossacklabs/acra/cmd/acra-keys/keys"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

func main() {
	keys.ParseParams()

	switch keys.Params.Command {
	case keys.CmdReadKey:
		printKey(keys.Params)
	case keys.CmdDestroyKey:
		destroyKey(keys.Params)
	}
}

func printKey(params *keys.CommandLineParams) {
	keyStore, err := keys.OpenKeyStoreForReading(params)
	if err != nil {
		log.WithError(err).Fatal("Failed to open key store")
	}

	keyBytes, err := keys.ReadKeyBytes(params, keyStore)
	if err != nil {
		log.WithError(err).Fatal("Failed to read key")
	}
	defer utils.ZeroizeSymmetricKey(keyBytes)

	_, err = os.Stdout.Write(keyBytes)
	if err != nil {
		log.WithError(err).Fatal("Failed to write key")
	}
}

func destroyKey(params *keys.CommandLineParams) {
	keyStore, err := keys.OpenKeyStoreForModification(params)
	if err != nil {
		log.WithError(err).Fatal("Failed to open key store")
	}

	err = keys.DestroyKey(params, keyStore)
	if err != nil {
		log.WithError(err).Fatal("Failed to destroy key")
	}
}
