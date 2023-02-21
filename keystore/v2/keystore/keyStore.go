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
	descriptions, err := DescribeKeyRings(keyRings, s)
	if err != nil {
		return nil, err
	}

	// we need to open each keyring to get the current key idx
	for i := 0; i < len(descriptions); i++ {
		ring, err := s.OpenKeyRing(descriptions[i].KeyID)
		if err != nil {
			log.WithError(err).Debug("Failed to open audit log key ring")
			return nil, err
		}

		currentKeyID, err := ring.CurrentKey()
		if err != nil {
			log.WithError(err).WithField("KeyID", descriptions[i].KeyID).Debug("Failed to get CurrentKeyID")
			return nil, err
		}

		creationTime, err := ring.ValidSince(currentKeyID)
		if err != nil {
			log.WithError(err).Debug("Failed to get creation time state by segnum")
			return nil, err
		}

		// 1 is virtual index of current key in keystore
		descriptions[i].Index = 1
		descriptions[i].CreationTime = &creationTime
		descriptions[i].State = keystore.StateCurrent
	}

	return descriptions, nil
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
		return s.listRotatedRings(path, poisonKeyPath, "")
	}

	if path == auditLogSymmetricKeyPath {
		return s.listRotatedRings(path, PurposeAuditLog, "")
	}
	if path == poisonSymmetricKeyPath {
		return s.listRotatedRings(path, poisonSymmetricKeyPath, "")
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
			return s.listRotatedRings(path, PurposeStorageClient, components[clientIDIndex])
		}
		if components[clientPrefixIndex] == clientPrefix && components[purposeIndex] == hmacSymmetricSuffix {
			return s.listRotatedRings(path, PurposeSearchHMAC, components[clientIDIndex])
		}
		if components[clientPrefixIndex] == clientPrefix && components[purposeIndex] == storageSymmetricSuffix {
			return s.listRotatedRings(path, PurposeStorageClientSym, components[clientIDIndex])
		}
	}

	return nil, ErrUnrecognizedKeyPurpose
}

// DescribeKeyRing describes key ring by its purpose path.
func (s *ServerKeyStore) DescribeKeyRing(path string) (*keystore.KeyDescription, error) {
	if path == poisonKeyPath {
		return &keystore.KeyDescription{
			KeyID:   path,
			Purpose: PurposePoisonRecord,
		}, nil
	}

	if path == auditLogSymmetricKeyPath {
		return &keystore.KeyDescription{
			KeyID:   path,
			Purpose: PurposeAuditLog,
		}, nil
	}
	if path == poisonSymmetricKeyPath {
		return &keystore.KeyDescription{
			KeyID:   path,
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
				KeyID:    path,
				Purpose:  PurposeStorageClient,
				ClientID: components[clientPrefixIndex],
			}, nil
		}
		if components[clientPrefixIndex] == clientPrefix && components[purposeIndex] == hmacSymmetricSuffix {
			return &keystore.KeyDescription{
				KeyID:    path,
				Purpose:  PurposeSearchHMAC,
				ClientID: components[clientPrefixIndex],
			}, nil
		}
		if components[clientPrefixIndex] == clientPrefix && components[purposeIndex] == storageSymmetricSuffix {
			return &keystore.KeyDescription{
				KeyID:    path,
				Purpose:  PurposeStorageClientSym,
				ClientID: components[clientIDIndex],
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

func (s *ServerKeyStore) listRotatedRings(path string, purpose keystore.KeyPurpose, clientID string) ([]keystore.KeyDescription, error) {
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
		keyState, err := ring.State(i)
		if err != nil {
			log.WithError(err).Debug("Failed to get key state by seqnum")
			return nil, err
		}

		// if the key was destroyed previously, ignore it
		if keyState == api.KeyDestroyed {
			continue
		}

		creationTime, err := ring.ValidSince(i)
		if err != nil {
			log.WithError(err).Debug("Failed to get creation time state by segnum")
			return nil, err
		}

		result = append(result, keystore.KeyDescription{
			// Index represent virtual index of key
			// 1 is always index of current key of the keystore
			// all rotated keys have index after 1
			Index:        i + 1,
			KeyID:        path,
			Purpose:      purpose,
			ClientID:     clientID,
			CreationTime: &creationTime,
			State:        keystore.StateRotated,
		})
	}

	return result, nil
}
