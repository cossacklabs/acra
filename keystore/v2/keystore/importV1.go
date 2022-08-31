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

package keystore

import (
	"errors"
	"github.com/cossacklabs/acra/keystore"

	filesystemV1 "github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/utils"
)

// Errors returned by key import:
var (
	ErrUnknownPurpose = errors.New("unknown key purpose")
)

// KeyFileImportV1 defines how filesystem keystore v1 keys are imported.
type KeyFileImportV1 interface {
	ImportKeyFileV1(oldKeyStore filesystemV1.KeyExport, key filesystemV1.ExportedKey) error
}

// ImportKeyFileV1 transfers key data from keystore version 1.
func (s *ServerKeyStore) ImportKeyFileV1(oldKeyStore filesystemV1.KeyExport, key filesystemV1.ExportedKey) error {
	keyID := keystore.GetKeyContextFromContext(key.KeyContext)
	log := s.log.WithField("purpose", key.KeyContext.Purpose).WithField("id", keyID)

	switch key.KeyContext.Purpose {
	case keystore.PurposePoisonRecordKeyPair:
		keypair, err := oldKeyStore.ExportKeyPair(key)
		if err != nil {
			log.WithError(err).Debug("failed to export poison record key pair")
			return err
		}
		defer utils.ZeroizeKeyPair(keypair)
		err = s.savePoisonKeyPair(keypair)
		if err != nil {
			log.WithError(err).Debug("failed to import poison record key pair")
			return err
		}
	case keystore.PurposeStorageClientKeyPair:
		keypair, err := oldKeyStore.ExportKeyPair(key)
		if err != nil {
			log.WithError(err).Debug("failed to export client storage key pair")
			return err
		}
		defer utils.ZeroizeKeyPair(keypair)
		err = s.SaveDataEncryptionKeys(keyID, keypair)
		if err != nil {
			log.WithError(err).Debug("failed to import client storage key pair")
			return err
		}
	case keystore.PurposeAuditLog:
		symkey, err := oldKeyStore.ExportSymmetricKey(key)
		if err != nil {
			log.WithError(err).Debug("Failed to export audit log key")
			return err
		}
		defer utils.ZeroizeSymmetricKey(symkey)
		err = s.importLogKey(symkey)
		if err != nil {
			log.WithError(err).Debug("Failed to import audit log key")
			return err
		}
	case keystore.PurposeSearchHMAC:
		symkey, err := oldKeyStore.ExportSymmetricKey(key)
		if err != nil {
			log.WithError(err).Debug("Failed to export search HMAC key")
			return err
		}
		defer utils.ZeroizeSymmetricKey(symkey)
		err = s.importHmacKey(keyID, symkey)
		if err != nil {
			log.WithError(err).Debug("Failed to import search HMAC key")
			return err
		}

	case keystore.PurposePoisonRecordSymmetricKey:
		symkey, err := oldKeyStore.ExportSymmetricKey(key)
		if err != nil {
			log.WithError(err).Debug("Failed to export poison record symmetric key")
			return err
		}
		defer utils.ZeroizeSymmetricKey(symkey)
		err = s.importPoisonRecordSymmetricKey(symkey)
		if err != nil {
			log.WithError(err).Debug("Failed to import poison record symmetric key")
			return err
		}

	case keystore.PurposeStorageClientSymmetricKey:
		symkey, err := oldKeyStore.ExportSymmetricKey(key)
		if err != nil {
			log.WithError(err).Debug("Failed to export client storage symmetric key")
			return err
		}
		defer utils.ZeroizeSymmetricKey(symkey)
		err = s.importClientIDSymmetricKey(keyID, symkey)
		if err != nil {
			log.WithError(err).Debug("Failed to import client storage symmetric key")
			return err
		}
	default:
		log.Debug("unknown key purpose")
		return ErrUnknownPurpose
	}
	return nil
}
