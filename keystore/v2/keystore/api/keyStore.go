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

// KeyStore securely keeps all of the client key data.
type KeyStore interface {
	// OpenKeyRing opens an existing key ring with given purpose.
	OpenKeyRing(purpose string) (KeyRing, error)

	// Close this keystore, releasing associated resources.
	// This generally renders opened KeyRings unusable.
	Close() error
}

// MutableKeyStore interface to KeyStore allowing write access.
type MutableKeyStore interface {
	KeyStore

	// OpenKeyRingRW opens a modifiable key ring with given purpose.
	// A new key ring will be created if it does not exist yet.
	OpenKeyRingRW(purpose string) (MutableKeyRing, error)
}
