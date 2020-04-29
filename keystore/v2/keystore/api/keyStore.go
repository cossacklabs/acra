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

// Package api describes API of Acra Key Store version 2.
package api

import (
	"github.com/cossacklabs/acra/keystore/v2/keystore/asn1"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
)

// KeyStore securely keeps all of the client key data.
type KeyStore interface {
	// OpenKeyRing opens an existing key ring with given purpose.
	OpenKeyRing(purpose string) (KeyRing, error)

	// Close this keystore, releasing associated resources.
	// This generally renders opened KeyRings unusable.
	Close() error

	// ExportKeyRings packages specified key rings for export.
	// Key ring data is encrypted and signed using given cryptosuite.
	// Resulting container can be imported into existing or different key store with ImportKeyRings().
	ExportKeyRings(paths []string, cryptosuite *crypto.KeyStoreSuite) ([]byte, error)
}

// MutableKeyStore interface to KeyStore allowing write access.
type MutableKeyStore interface {
	KeyStore

	// OpenKeyRingRW opens a modifiable key ring with given purpose.
	// A new key ring will be created if it does not exist yet.
	OpenKeyRingRW(purpose string) (MutableKeyRing, error)

	// ImportKeyRings unpacks key rings packaged by ExportKeyRings.
	// The provided cryptosuite is used to verify the signature on the container and decrypt key ring data.
	// Optional delegate can be used to control various aspects of the import process, such as conflict resolution.
	ImportKeyRings(exportData []byte, cryptosuite *crypto.KeyStoreSuite, delegate *KeyRingImportDelegate) error
}

// ImportDecision constants describe how to proceed with import conflict resolution.
type ImportDecision int

// ImportDecision options.
const (
	// Do not modify existing key ring, abort with given error.
	ImportAbort ImportDecision = iota
	// Do not modify existing key ring, proceed with importing others.
	ImportSkip
	// Overwrite existing key ring with new data.
	ImportOverwrite
)

// KeyRingImportDelegate controls details of key ring import process.
type KeyRingImportDelegate struct {
	// This callback is executed when an imported key ring already exists.
	// If not set, import process will be aborted.
	// Current key ring content is encrypted, new key ring content is in plain.
	// Don't look at the key material, decide based on validity ranges and sequence numbers.
	DecideKeyRingOverwrite func(currentData, newData *asn1.KeyRing) (ImportDecision, error)
}
