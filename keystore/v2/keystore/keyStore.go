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

// Package keystore implements Acra Keystore version 2.
package keystore

import (
	"errors"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
)

const serviceName = "keystore"

// Errors for describing keys
var (
	ErrUnrecognizedKeyPurpose = errors.New("key purpose not recognized")
)

const (
	clientPrefixIndex = iota
	clientIDIndex
	purposeIndex
)

// Key purpose constants.
const (
	PurposePoisonRecord     = "poison record key"
	PurposeStorageClient    = "client storage key"
	PurposeAuditLog         = "audit log signature key"
	PurposePoisonSym        = "poison record symmetric key"
	PurposeStorageClientSym = "client storage symmetric key"
	PurposeSearchHMAC       = "encrypted search HMAC key"
)

// ServerKeyStore provides full access to Acra Keystore.
//
// It is intended to be used by AcraServer components and uses server transport keys.
type ServerKeyStore struct {
	api.MutableKeyStore
	log *log.Entry
}

// TranslatorKeyStore provides access to Acra Keystore for AcraTranslator.
//
// This is the same as ServerKeyStore, but with AcraTranslator transport keys.
type TranslatorKeyStore struct {
	ServerKeyStore
}

// NewServerKeyStore configures keystore for AcraServer.
func NewServerKeyStore(keyStore api.MutableKeyStore) *ServerKeyStore {
	return &ServerKeyStore{keyStore, log.WithField("service", serviceName)}
}

// NewTranslatorKeyStore configures keystore for AcraTranslator
func NewTranslatorKeyStore(keyStore api.MutableKeyStore) *TranslatorKeyStore {
	return &TranslatorKeyStore{
		ServerKeyStore{keyStore, log.WithField("service", serviceName)},
	}
}

// ListRotatedKeys enumerates rotated keys present in the keystore.
func (s *ServerKeyStore) ListRotatedKeys() ([]keystore.KeyDescription, error) {
	keyRings, err := s.ListKeyRings()
	if err != nil {
		return nil, err
	}
	return DescribeRotatedKeyRings(keyRings, s)
}

// ListKeys enumerates keys present in the keystore.
func (s *ServerKeyStore) ListKeys() ([]keystore.KeyDescription, error) {
	keyRings, err := s.ListKeyRings()
	if err != nil {
		return nil, err
	}
	return DescribeKeyRings(keyRings, s)
}

// CacheOnStart v2 keystore doesnt support keys caching
func (s *ServerKeyStore) CacheOnStart() error {
	panic("caching is not implemented for keystore v2")
}

// DescribeKeyRings describes multiple key rings by their purpose paths.
func DescribeKeyRings(keyRings []string, keyStore api.KeyStore) ([]keystore.KeyDescription, error) {
	keys := make([]keystore.KeyDescription, len(keyRings))
	for i := range keys {
		description, err := keyStore.DescribeKeyRing(keyRings[i])
		if err != nil {
			return nil, err
		}
		keys[i] = *description
	}
	return keys, nil
}

// DescribeRotatedKeyRings describes multiple key rings by their purpose paths.
func DescribeRotatedKeyRings(keyRings []string, keyStore api.KeyStore) ([]keystore.KeyDescription, error) {
	keys := make([]keystore.KeyDescription, 0, len(keyRings))
	for i := range keyRings {
		descriptions, err := keyStore.DescribeRotatedKeyRing(keyRings[i])
		if err != nil {
			return nil, err
		}
		keys = append(keys, descriptions...)
	}
	return keys, nil
}

// DescribeRotatedKeyRing describes key ring by its purpose path.
func (s *ServerKeyStore) DescribeRotatedKeyRing(path string) ([]keystore.KeyDescription, error) {
	if path == poisonKeyPath {
		return s.listRotatedRings(path, poisonKeyPath, []byte{})
	}

	if path == auditLogSymmetricKeyPath {
		return s.listRotatedRings(path, PurposeAuditLog, []byte{})
	}
	if path == poisonSymmetricKeyPath {
		return s.listRotatedRings(path, poisonSymmetricKeyPath, []byte{})
	}

	// Paths which are not server-global symmetric keys look like this:
	//
	//     client/${client_id}/storage
	//
	// Split them into components by slashes and parse the result.
	//components := strings.Split(path, string(filepath.Separator))
	components := strings.Split(path, string(filepath.Separator))
	if len(components) == 3 {
		if components[clientPrefixIndex] == clientPrefix && components[purposeIndex] == storageSuffix {
			return s.listRotatedRings(path, PurposeStorageClient, []byte(components[clientIDIndex]))
		}
		if components[clientPrefixIndex] == clientPrefix && components[purposeIndex] == hmacSymmetricSuffix {
			return s.listRotatedRings(path, PurposeSearchHMAC, []byte(components[clientIDIndex]))
		}
		if components[clientPrefixIndex] == clientPrefix && components[purposeIndex] == storageSymmetricSuffix {
			return s.listRotatedRings(path, PurposeStorageClientSym, []byte(components[clientIDIndex]))
		}
	}

	return nil, ErrUnrecognizedKeyPurpose
}

// DescribeKeyRing describes key ring by its purpose path.
func (s *ServerKeyStore) DescribeKeyRing(path string) (*keystore.KeyDescription, error) {
	if path == poisonKeyPath {
		return &keystore.KeyDescription{
			ID:      path,
			Purpose: PurposePoisonRecord,
		}, nil
	}

	if path == auditLogSymmetricKeyPath {
		return &keystore.KeyDescription{
			ID:      path,
			Purpose: PurposeAuditLog,
		}, nil
	}
	if path == poisonSymmetricKeyPath {
		return &keystore.KeyDescription{
			ID:      path,
			Purpose: PurposePoisonSym,
		}, nil
	}

	// Paths which are not server-global symmetric keys look like this:
	//
	//     client/${client_id}/storage
	//
	// Split them into components by slashes and parse the result.
	components := strings.Split(path, string(filepath.Separator))
	if len(components) == 3 {
		if components[clientPrefixIndex] == clientPrefix && components[purposeIndex] == storageSuffix {
			return &keystore.KeyDescription{
				ID:       path,
				Purpose:  PurposeStorageClient,
				ClientID: []byte(components[clientPrefixIndex]),
			}, nil
		}
		if components[clientPrefixIndex] == clientPrefix && components[purposeIndex] == hmacSymmetricSuffix {
			return &keystore.KeyDescription{
				ID:       path,
				Purpose:  PurposeSearchHMAC,
				ClientID: []byte(components[clientPrefixIndex]),
			}, nil
		}
		if components[clientPrefixIndex] == clientPrefix && components[purposeIndex] == storageSymmetricSuffix {
			return &keystore.KeyDescription{
				ID:       path,
				Purpose:  PurposeStorageClientSym,
				ClientID: []byte(components[clientIDIndex]),
			}, nil
		}
	}

	return nil, ErrUnrecognizedKeyPurpose
}

// Reset is a compatibility method that does nothing.
// In KeyStoreV1 this method is used to reset cache.
// KeyStoreV2 currently does not support key caching so there is nothing to reset.
func (s *ServerKeyStore) Reset() {
}

func (s *ServerKeyStore) listRotatedRings(path string, purpose keystore.KeyPurpose, clientID []byte) ([]keystore.KeyDescription, error) {
	ring, err := s.OpenKeyRing(path)
	if err != nil {
		log.WithError(err).Debug("Failed to open audit log key ring")
		return nil, err
	}

	keys, err := ring.AllKeys()
	if err != nil {
		log.WithError(err).Debug("Failed to read all key ids")
		return nil, err
	}

	if len(keys) == 0 {
		return []keystore.KeyDescription{}, nil
	}

	result := make([]keystore.KeyDescription, 0, len(keys)-1)
	for i := 1; i < len(keys); i++ {
		creationTime, err := ring.ValidSince(i)
		if err != nil {
			log.WithError(err).Debug("Failed to get creation time state by segnum")
			return nil, err
		}

		result = append(result, keystore.KeyDescription{
			ID:           path,
			Purpose:      purpose,
			ClientID:     clientID,
			CreationTime: creationTime,
		})
	}

	return result, nil
}
