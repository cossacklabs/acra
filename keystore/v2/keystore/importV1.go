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

	filesystemV1 "github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
)

// Errors returned by key import:
var (
	ErrUnknownPurpose = errors.New("unknown key purpose")
)

// KeyFileImportV1 defines how filesystem key store v1 keys are imported.
type KeyFileImportV1 interface {
	ImportKeyFileV1(oldKeyStore filesystemV1.KeyExport, key filesystemV1.ExportedKey) error
}

// ImportKeyFileV1 transfers key data from keystore version 1.
func (s *ServerKeyStore) ImportKeyFileV1(oldKeyStore filesystemV1.KeyExport, key filesystemV1.ExportedKey) error {
	log := s.log.WithField("purpose", key.Purpose).WithField("id", key.ID)
	switch key.Purpose {
	case filesystemV1.PurposeAuthenticationSymKey:
		symkey, err := oldKeyStore.ExportPlaintextSymmetricKey(key)
		if err != nil {
			log.WithError(err).Debug("failed to export authentication key")
			return err
		}
		defer zeroizeSymmetricKey(symkey)
		err = s.saveAuthKey(symkey)
		if err != nil {
			log.WithError(err).Debug("failed to import authentication key")
			return err
		}
	case filesystemV1.PurposePoisonRecordKeyPair:
		keypair, err := oldKeyStore.ExportKeyPair(key)
		if err != nil {
			log.WithError(err).Debug("failed to export poison record key pair")
			return err
		}
		defer zeroizeKeyPair(keypair)
		err = s.savePoisonKeyPair(keypair)
		if err != nil {
			log.WithError(err).Debug("failed to import poison record key pair")
			return err
		}
	case filesystemV1.PurposeStorageClientKeyPair:
		keypair, err := oldKeyStore.ExportKeyPair(key)
		if err != nil {
			log.WithError(err).Debug("failed to export client storage key pair")
			return err
		}
		defer zeroizeKeyPair(keypair)
		err = s.SaveDataEncryptionKeys(key.ID, keypair)
		if err != nil {
			log.WithError(err).Debug("failed to import client storage key pair")
			return err
		}
	case filesystemV1.PurposeStorageZoneKeyPair:
		keypair, err := oldKeyStore.ExportKeyPair(key)
		if err != nil {
			log.WithError(err).Debug("failed to export zone storage key pair")
			return err
		}
		defer zeroizeKeyPair(keypair)
		err = s.SaveZoneKeypair(key.ID, keypair)
		if err != nil {
			log.WithError(err).Debug("failed to import zone storage key pair")
			return err
		}
	case filesystemV1.PurposeTransportConnectorKeyPair:
		keypair, err := oldKeyStore.ExportKeyPair(key)
		if err != nil {
			log.WithError(err).Debug("failed to export AcraConnector transport key pair")
			return err
		}
		defer zeroizeKeyPair(keypair)
		err = s.SaveConnectorKeypair(key.ID, keypair)
		if err != nil {
			log.WithError(err).Debug("failed to import AcraConnector transport key pair")
			return err
		}
	case filesystemV1.PurposeTransportTranslatorKeyPair:
		keypair, err := oldKeyStore.ExportKeyPair(key)
		if err != nil {
			log.WithError(err).Debug("failed to export AcraTranslator transport key pair")
			return err
		}
		defer zeroizeKeyPair(keypair)
		err = s.SaveTranslatorKeypair(key.ID, keypair)
		if err != nil {
			log.WithError(err).Debug("failed to import AcraTranslator transport key pair")
			return err
		}
	case filesystemV1.PurposeTransportServerKeyPair:
		keypair, err := oldKeyStore.ExportKeyPair(key)
		if err != nil {
			log.WithError(err).Debug("failed to export AcraServer transport key pair")
			return err
		}
		defer zeroizeKeyPair(keypair)
		err = s.SaveServerKeypair(key.ID, keypair)
		if err != nil {
			log.WithError(err).Debug("failed to import AcraServer transport key pair")
			return err
		}
	default:
		log.Debug("unknown key purpose")
		return ErrUnknownPurpose
	}
	return nil
}

func zeroizeSymmetricKey(key []byte) {
	utils.FillSlice(0, key)
}

func zeroizeKeyPair(keypair *keys.Keypair) {
	if keypair.Private != nil {
		utils.FillSlice(0, keypair.Private.Value)
	}
}
