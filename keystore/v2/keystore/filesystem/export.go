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

package filesystem

import (
	"errors"
	"time"

	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/asn1"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	backendAPI "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/signature"
	"github.com/cossacklabs/acra/utils"
)

// Errors returned by export/import routines.
var (
	ErrKeyRingExists = errors.New("imported key ring already exists")
	ErrNoPublicData  = errors.New("key has no public data")
)

func (s *KeyStore) exportKeyRings(paths []string, mode api.ExportMode) (rings []asn1.KeyRing, err error) {
	rings = make([]asn1.KeyRing, 0, len(paths))
	defer func() {
		if err != nil {
			zeroizeKeyRings(rings)
		}
	}()
	for _, path := range paths {
		ring, err := s.exportKeyRing(path, mode)
		if err == ErrNoPublicData {
			s.log.Infof("Key not exported: %s (%v)", path, err)
			continue
		}
		if err != nil {
			return nil, err
		}
		rings = append(rings, ring)
	}
	return rings, nil
}

func (s *KeyStore) exportKeyRing(path string, mode api.ExportMode) (asn1.KeyRing, error) {
	ring := newKeyRing(s, path)
	err := s.readKeyRing(ring)
	if err != nil {
		return asn1.KeyRing{}, err
	}
	ringData, err := ring.exportASN1(mode)
	if err != nil {
		return asn1.KeyRing{}, err
	}
	return ringData, nil
}

func (s *KeyStore) importKeyRing(newRingData *asn1.KeyRing, delegate api.KeyRingImportDelegate) error {
	keyRing := newKeyRing(s, string(newRingData.Purpose))
	// Try reading the key ring. If it succeeds, the key ring already exists.
	err := s.readKeyRing(keyRing)
	switch err {
	case nil:
		// If the keystore successfuly returned an existing key ring with the same name,
		// we have to resolve this conflict somehow. Present both current and new versions
		// to the delegate and let it decide how to proceed.
		decision, err := delegate.DecideKeyRingOverwrite(keyRing.data, newRingData)
		switch decision {
		case api.ImportOverwrite:
			// Forget whatever we just read and import into a clean key ring.
			keyRing = newKeyRing(s, string(newRingData.Purpose))
			err := keyRing.importASN1(newRingData)
			if err != nil {
				return err
			}
			return nil
		case api.ImportSkip:
			return nil
		default:
			return err
		}

	case backendAPI.ErrNotExist:
		// If the key ring does not seem to exist right now, go ahead with clean-slate import.
		err := s.openKeyRing(keyRing)
		if err != nil {
			return err
		}
		err = keyRing.importASN1(newRingData)
		if err != nil {
			return err
		}
		return nil

	default:
		// Otherwise, this is some unexpected error from the keystore. Abort import and get out.
		return err
	}
}

var exportKeyContext = []byte("AKSv2 keystore: exported key rings")

func (s *KeyStore) encryptAndSignKeyRings(rings []asn1.KeyRing, cryptosuite *crypto.KeyStoreSuite) ([]byte, error) {
	keysData := &asn1.EncryptedKeys{KeyRings: rings}
	keysBytes, err := keysData.Marshal()
	if err != nil {
		return nil, err
	}
	defer utils.FillSlice(0, keysBytes)

	encryptedKeyBytes, err := cryptosuite.KeyEncryptor.Encrypt(keysBytes, exportKeyContext)
	if err != nil {
		return nil, err
	}
	container := asn1.SignedContainer{Payload: asn1.SignedPayload{
		ContentType:  asn1.TypeEncryptedKeys,
		Version:      asn1.KeyRingVersion2,
		LastModified: time.Now(),
		Data:         encryptedKeyBytes,
	}}

	notary, err := signature.NewNotary(cryptosuite.SignatureAlgorithms)
	if err != nil {
		return nil, err
	}
	signedKeyContainer, err := notary.Sign(&container, exportKeyContext)
	if err != nil {
		return nil, err
	}
	return signedKeyContainer, nil
}

func (s *KeyStore) decryptAndVerifyKeyRings(ringData []byte, cryptosuite *crypto.KeyStoreSuite) ([]asn1.KeyRing, error) {
	notary, err := signature.NewNotary(cryptosuite.SignatureAlgorithms)
	if err != nil {
		return nil, err
	}
	container, err := notary.Verify(ringData, exportKeyContext)
	if err != nil {
		return nil, err
	}
	if container.Payload.ContentType != asn1.TypeEncryptedKeys {
		return nil, errIncorrectContentType
	}
	if container.Payload.Version != asn1.KeyRingVersion2 {
		return nil, errUnsupportedVersion
	}

	decryptedKeyBytes, err := cryptosuite.KeyEncryptor.Decrypt(container.Payload.Data.Bytes, exportKeyContext)
	if err != nil {
		return nil, err
	}
	defer utils.FillSlice(0, decryptedKeyBytes)

	keys, err := asn1.UnmarshalEncryptedKeys(decryptedKeyBytes)
	if err != nil {
		return nil, err
	}

	return keys.KeyRings, nil
}

func (r *KeyRing) exportASN1(mode api.ExportMode) (exported asn1.KeyRing, err error) {
	exported = asn1.KeyRing{
		Purpose: r.data.Purpose,
		Current: r.data.Current,
		Keys:    make([]asn1.Key, len(r.data.Keys)),
	}
	copy(exported.Keys, r.data.Keys)
	defer func() {
		if err != nil {
			zeroizeKeyRing(&exported)
		}
	}()
	for i := range exported.Keys {
		decrypted, err := r.decryptAllKeyData(exported.Keys[i].Data, exported.Keys[i].Seqnum, mode)
		if err != nil {
			return exported, err
		}
		exported.Keys[i].Data = decrypted
	}
	return exported, nil
}

func (r *KeyRing) importASN1(ringData *asn1.KeyRing) error {
	// Make properly encrypted copies of key data.
	newKeys := make([]asn1.Key, len(ringData.Keys))
	for i := range ringData.Keys {
		newKey, err := r.copyKey(&ringData.Keys[i])
		if err != nil {
			return err
		}
		newKeys[i] = *newKey
	}
	r.pushTX(&txSetKeys{newKeys: newKeys, current: ringData.Current})
	err := r.store.syncKeyRing(r)
	if err != nil {
		r.popTX()
	}
	return err
}

func (r *KeyRing) decryptAllKeyData(encrypted []asn1.KeyData, seqnum int, mode api.ExportMode) (decrypted []asn1.KeyData, err error) {
	decrypted = make([]asn1.KeyData, len(encrypted))
	copy(decrypted, encrypted)
	defer func() {
		if err != nil {
			zeroizeKeyData(decrypted)
		}
	}()
	for i := range decrypted {
		err = r.decryptKeyData(&decrypted[i], seqnum, mode)
		if err != nil {
			return nil, err
		}
	}
	return decrypted, nil
}

func (r *KeyRing) decryptKeyData(data *asn1.KeyData, seqnum int, mode api.ExportMode) error {
	// If we do not export private key data then remove it without decryption.
	// If there is no public key data left then this is a symmetric key and we need to skip it.
	if mode&api.ExportPrivateKeys == 0 {
		data.PrivateKey = nil
		data.SymmetricKey = nil
		if len(data.PublicKey) == 0 {
			return ErrNoPublicData
		}
		return nil
	}

	if len(data.PrivateKey) != 0 {
		privateKey, err := r.decryptPrivateKey(seqnum, data.PrivateKey)
		if err != nil {
			return err
		}
		data.PrivateKey = privateKey
	}
	if len(data.SymmetricKey) != 0 {
		symmetricKey, err := r.decryptSymmetricKey(seqnum, data.SymmetricKey)
		if err != nil {
			return err
		}
		data.SymmetricKey = symmetricKey
	}
	return nil
}

func zeroizeKeyRings(rings []asn1.KeyRing) {
	for i := range rings {
		zeroizeKeyRing(&rings[i])
	}
}

func zeroizeKeyRing(ring *asn1.KeyRing) {
	for i := range ring.Keys {
		zeroizeKeyData(ring.Keys[i].Data)
	}
}

func zeroizeKeyData(data []asn1.KeyData) {
	for i := range data {
		utils.FillSlice(0, data[i].PrivateKey)
		utils.FillSlice(0, data[i].PublicKey)
		utils.FillSlice(0, data[i].SymmetricKey)
	}
}
