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

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	acrastruct2 "github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
)

// RotateStorageKeyStore enables storage key rotation. It is used by acra-rotate tool.
type RotateStorageKeyStore interface {
	keystore.StorageKeyCreation
	keystore.DataEncryptorKeyStore
}

type keyRotator struct {
	keystore    RotateStorageKeyStore
	newKeypairs map[string]*keys.Keypair
	zoneMode    bool
}

func newRotator(store RotateStorageKeyStore, zoneMode bool) (*keyRotator, error) {
	return &keyRotator{keystore: store, newKeypairs: make(map[string]*keys.Keypair), zoneMode: zoneMode}, nil
}
func (rotator *keyRotator) getRotatedPublicKey(keyID []byte) (*keys.PublicKey, error) {
	keypair, ok := rotator.newKeypairs[string(keyID)]
	if ok {
		return keypair.Public, nil
	}
	newKeypair, err := keys.New(keys.TypeEC)
	if err != nil {
		return nil, err
	}
	rotator.newKeypairs[string(keyID)] = newKeypair
	return newKeypair.Public, nil
}

func (rotator *keyRotator) rotateAcrastructWithZone(zoneID, data []byte) ([]byte, error) {
	logger := log.WithFields(log.Fields{"ZoneId": string(zoneID)})
	logger.Infof("Rotate AcraStruct")
	// rotate
	handler, err := crypto.GetHandlerByEnvelopeID(crypto.AcraStructEnvelopeID)
	if err != nil {
		log.WithError(err).Errorln("Can't load handler by envelope ID")
		return nil, err
	}
	accessContext := base.NewAccessContext(base.WithZoneMode(true))
	accessContext.SetZoneID(zoneID)
	dataContext := &base.DataProcessorContext{Keystore: rotator.keystore,
		Context: base.SetAccessContextToContext(context.Background(), accessContext)}
	acrastruct, envelopeID, err := crypto.DeserializeEncryptedData(data)
	if err != nil {
		logger.WithError(err).Errorln("Can't deserialize container")
		return nil, err
	}
	if envelopeID != crypto.AcraStructEnvelopeID {
		logger.WithField("envelope_id", envelopeID).WithError(err).Errorln("Incorrect envelope ID in container, not AcraStruct")
		return nil, err
	}
	decrypted, err := handler.Decrypt(acrastruct, dataContext)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't decrypt AcraStruct")
		return nil, err
	}
	defer utils.ZeroizeBytes(decrypted)
	publicKey, err := rotator.getRotatedPublicKey(zoneID)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't load public key")
		return nil, err
	}
	rotated, err := acrastruct2.CreateAcrastruct(decrypted, publicKey, zoneID)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't rotate data")
		return nil, err
	}
	rotated, err = crypto.SerializeEncryptedData(rotated, crypto.AcraStructEnvelopeID)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't serialize data")
		return nil, err
	}
	return rotated, nil
}

func (rotator *keyRotator) rotateAcrastruct(id, acrastruct []byte) ([]byte, error) {
	if rotator.zoneMode {
		return rotator.rotateAcrastructWithZone(id, acrastruct)
	}
	return rotator.rotateAcrastructWithClientID(id, acrastruct)
}

func (rotator *keyRotator) rotateAcrastructWithClientID(clientID, data []byte) ([]byte, error) {
	logger := log.WithFields(log.Fields{"KeyID": string(clientID)})
	logger.Infof("Rotate AcraStruct")
	// rotate
	handler, err := crypto.GetHandlerByEnvelopeID(crypto.AcraStructEnvelopeID)
	if err != nil {
		log.WithError(err).Errorln("Can't load handler by envelope ID")
		return nil, err
	}
	accessContext := base.NewAccessContext(base.WithClientID(clientID))
	dataContext := &base.DataProcessorContext{Keystore: rotator.keystore,
		Context: base.SetAccessContextToContext(context.Background(), accessContext)}
	acrastruct, envelopeID, err := crypto.DeserializeEncryptedData(data)
	if err != nil {
		logger.WithError(err).Errorln("Can't deserialize container")
		return nil, err
	}
	if envelopeID != crypto.AcraStructEnvelopeID {
		logger.WithField("envelope_id", envelopeID).WithError(err).Errorln("Incorrect envelope ID in container, not AcraStruct")
		return nil, err
	}
	decrypted, err := handler.Decrypt(acrastruct, dataContext)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't decrypt AcraStruct")
		return nil, err
	}
	defer utils.ZeroizeBytes(decrypted)
	publicKey, err := rotator.getRotatedPublicKey(clientID)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't load public key")
		return nil, err
	}
	rotated, err := acrastruct2.CreateAcrastruct(decrypted, publicKey, nil)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't rotate data")
		return nil, err
	}
	rotated, err = crypto.SerializeEncryptedData(rotated, crypto.AcraStructEnvelopeID)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't serialize data")
		return nil, err
	}
	return rotated, nil
}

func (rotator *keyRotator) saveRotatedKey(id []byte, keypair *keys.Keypair) error {
	if rotator.zoneMode {
		return rotator.keystore.SaveZoneKeypair(id, keypair)
	}
	return rotator.keystore.SaveDataEncryptionKeys(id, keypair)
}

func (rotator *keyRotator) saveRotatedKeys() error {
	for id, keypair := range rotator.newKeypairs {
		if err := rotator.saveRotatedKey([]byte(id), keypair); err != nil {
			log.WithField("key_id", id).
				WithField("zone_mode", rotator.zoneMode).
				WithError(err).Errorln("Can't save rotated keypair")
			return err
		}
	}
	return nil
}

func (rotator *keyRotator) clearKeys() {
	for _, keypair := range rotator.newKeypairs {
		utils.ZeroizePrivateKey(keypair.Private)
	}
}

func (rotator *keyRotator) marshal() ([]byte, error) {
	const PublicKey = "new_public_key"
	output := make(map[string]map[string][]byte)
	for id, keypair := range rotator.newKeypairs {
		output[string(id)] = map[string][]byte{PublicKey: keypair.Public.Value}
	}
	return json.Marshal(output)
}
