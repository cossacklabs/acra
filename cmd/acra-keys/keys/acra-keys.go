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

// Package keys defines reusable business logic of `acra-keys` utility.
package keys

import (
	"io"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
)

// ListKeysCommand implements the "list" command.
func ListKeysCommand(params ListKeysParams, keyStore keystore.ServerKeyStore) {
	keyDescriptions, err := keyStore.ListKeys()
	if err != nil {
		log.WithError(err).Fatal("Failed to read key list")
	}

	err = PrintKeys(keyDescriptions, os.Stdout, params)
	if err != nil {
		log.WithError(err).Fatal("Failed to print key list")
	}

	if params.ListRotatedKeys() {
		keyDescriptions, err = keyStore.ListRotatedKeys()
		if err != nil {
			log.WithError(err).Fatal("Failed to read key list")
		}

		err = PrintRotatedKeys(keyDescriptions, os.Stdout, params)
		if err != nil {
			log.WithError(err).Fatal("Failed to print key list")
		}
	}
}

// PrintKeyCommand implements the "read" command.
func (p *ReadKeySubcommand) PrintKeyCommand(params ReadKeyParams, keyStore keystore.ServerKeyStore) {
	keyBytes, err := ReadKeyBytes(params, keyStore)
	if err != nil {
		log.WithError(err).Fatal("Failed to read key")
	}
	defer utils.ZeroizeSymmetricKey(keyBytes)
	// allow to override writer for tests purpose with IDEA support
	// https://github.com/go-lang-plugin-org/go-lang-idea-plugin/issues/2439
	// IDEA marks test-cases as terminated if something in tests writes to stdout due to using json format and invalid output
	// https://github.com/golang/go/issues/23036
	// but by default it should write to StdOut to be able to pipe out output to next command
	var writer io.Writer = os.Stdout
	if p.outWriter != nil {
		writer = p.outWriter
	}
	_, err = writer.Write(keyBytes)
	if err != nil {
		log.WithError(err).Fatal("Failed to write key")
	}
}

// DestroyKeyCommand implements the "destroy" command.
func DestroyKeyCommand(params DestroyKeyParams, keyStore keystore.KeyMaking) {
	err := DestroyKey(params, keyStore)
	if err != nil {
		log.WithError(err).Fatal("Failed to destroy key")
	}
}
