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
	"github.com/cossacklabs/acra/acra-writer"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
)

type keyRotator struct {
	keystore    keystore.KeyStore
	newKeypairs map[string]*keys.Keypair
}

func newRotator(store keystore.KeyStore) (*keyRotator, error) {
	return &keyRotator{keystore: store, newKeypairs: make(map[string]*keys.Keypair)}, nil
}
func (rotator *keyRotator) getRotatedPublicKey(zoneID []byte) (*keys.PublicKey, error) {
	keypair, ok := rotator.newKeypairs[string(zoneID)]
	if ok {
		return keypair.Public, nil
	}
	newKeypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		return nil, err
	}
	rotator.newKeypairs[string(zoneID)] = newKeypair
	return newKeypair.Public, nil
}

func (rotator *keyRotator) rotateAcrastruct(zoneID, acrastruct []byte) ([]byte, error) {
	logger := log.WithFields(log.Fields{"ZoneId": string(zoneID)})
	logger.Infof("Rotate AcraStruct")
	// rotate
	privateKey, err := rotator.keystore.GetZonePrivateKey(zoneID)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't get private key")
		return nil, err
	}
	decrypted, err := base.DecryptAcrastruct(acrastruct, privateKey, zoneID)
	if err != nil {
		logger.WithField("acrastruct", hex.EncodeToString(acrastruct)).WithError(err).Errorln("Can't decrypt AcraStruct")
		return nil, err
	}
	utils.FillSlice(0, privateKey.Value)
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
	utils.FillSlice(0, decrypted)
	return rotated, nil
}

func (rotator *keyRotator) saveRotatedKeys() error {
	for zoneID, keypair := range rotator.newKeypairs {
		if err := rotator.keystore.SaveZoneKeypair([]byte(zoneID), keypair); err != nil {
			log.WithField("zoneID", zoneID).WithError(err).Errorln("Can't save rotated keypair")
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
