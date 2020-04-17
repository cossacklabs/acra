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
	"encoding/hex"
	"encoding/json"

	acrawriter "github.com/cossacklabs/acra/acra-writer"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
)

type keyRotator struct {
	keystore    keystore.RotateStorageKeyStore
	newKeypairs map[string]*keys.Keypair
	zoneMode    bool
}

func newRotator(store keystore.RotateStorageKeyStore, zoneMode bool) (*keyRotator, error) {
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

func (rotator *keyRotator) rotateAcrastructWithZone(zoneID, acrastruct []byte) ([]byte, error) {
	logger := log.WithFields(log.Fields{"ZoneId": string(zoneID)})
	logger.Infof("Rotate AcraStruct")
	// rotate
	privateKeys, err := rotator.keystore.GetZonePrivateKeys(zoneID)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't get private key")
		return nil, err
	}
	defer utils.ZeroizePrivateKeys(privateKeys)
	decrypted, err := base.DecryptRotatedAcrastruct(acrastruct, privateKeys, zoneID)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't decrypt AcraStruct")
		return nil, err
	}
	defer utils.FillSlice(0, decrypted)
	publicKey, err := rotator.getRotatedPublicKey(zoneID)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't load public key")
		return nil, err
	}
	rotated, err := acrawriter.CreateAcrastruct(decrypted, publicKey, zoneID)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't rotate data")
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

func (rotator *keyRotator) rotateAcrastructWithClientID(clientID, acrastruct []byte) ([]byte, error) {
	logger := log.WithFields(log.Fields{"KeyID": string(clientID)})
	logger.Infof("Rotate AcraStruct")
	// rotate
	privateKeys, err := rotator.keystore.GetServerDecryptionPrivateKeys(clientID)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't get private key")
		return nil, err
	}
	defer utils.ZeroizePrivateKeys(privateKeys)
	decrypted, err := base.DecryptRotatedAcrastruct(acrastruct, privateKeys, nil)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't decrypt AcraStruct")
		return nil, err
	}
	defer utils.FillSlice(0, decrypted)
	publicKey, err := rotator.getRotatedPublicKey(clientID)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't load public key")
		return nil, err
	}
	rotated, err := acrawriter.CreateAcrastruct(decrypted, publicKey, nil)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't rotate data")
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
		utils.FillSlice(0, keypair.Private.Value)
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
