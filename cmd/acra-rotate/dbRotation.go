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
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/cossacklabs/acra/acra-writer"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
	"reflect"
)

type keyPair struct {
	oldPrivatekey *keys.PrivateKey
	NewPublicKey  *keys.PublicKey
}

// keyRotatationStore store previous privateKeys and new public keys after rotation to use same private/public keys during rotation
type keyRotatationStore struct {
	keys     map[string]*keyPair
	keystore keystore.KeyStore
}

// Marshal encode new public keys for zones to json
func (store *keyRotatationStore) Marshal() ([]byte, error) {
	// encode to json in compatible format as in file rotation
	const PublicKey = "new_public_key"
	output := make(map[string]map[string][]byte)
	for id, keypair := range store.keys {
		output[id] = map[string][]byte{PublicKey: keypair.NewPublicKey.Value}
	}
	return json.Marshal(output)
}

// rotateKey load current private key to memory, rotate and save new public key in memory
func (store *keyRotatationStore) rotateKey(id []byte) error {
	idStr := string(id)
	privateKey, err := store.keystore.GetZonePrivateKey(id)
	if err != nil {
		log.WithError(err).Errorf("Can't load current private key of zone=%s", string(id))
		return err
	}
	newPublicKey, err := store.keystore.RotateZoneKey(id)
	if err != nil {
		log.WithError(err).Errorf("Rotate private key of zone=%s", string(id))
		return err
	}
	store.keys[idStr] = &keyPair{oldPrivatekey: privateKey, NewPublicKey: &keys.PublicKey{newPublicKey}}
	return nil
}

// getPublicKey return new rotated public key of zone
func (store *keyRotatationStore) getPublicKey(id []byte) (*keys.PublicKey, error) {
	idStr := string(id)
	if keypair, ok := store.keys[idStr]; ok {
		return keypair.NewPublicKey, nil
	}
	if err := store.rotateKey(id); err != nil {
		return nil, err
	}
	keypair := store.keys[idStr]
	return keypair.NewPublicKey, nil
}

// getPrivateKey return private key before rotation
func (store *keyRotatationStore) getPrivateKey(id []byte) (*keys.PrivateKey, error) {
	idStr := string(id)
	if keypair, ok := store.keys[idStr]; ok {
		return keypair.oldPrivatekey, nil
	}
	if err := store.rotateKey(id); err != nil {
		return nil, err
	}
	keypair := store.keys[idStr]
	return keypair.oldPrivatekey, nil
}

// rotateDb execute selectQuery to fetch AcraStructs with related zone ids, decrypt with rotated zone keys and
func rotateDb(selectQuery, updateQuery string, db *sql.DB, keystore keystore.KeyStore) bool {
	rows, err := db.Query(selectQuery)
	if err != nil {
		log.WithError(err).Errorf("Can't fetch result")
		return false
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		log.WithError(err).Errorln("Can't fetch info about result columns")
		return false
	}
	if len(columns) < 2 {
		log.Errorln("Result has < 2 columns. Expected at least ZoneId and AcraStruct")
		return false
	}

	keysStore := &keyRotatationStore{keystore: keystore, keys: make(map[string]*keyPair)}

	row := make([]interface{}, len(columns))
	rowPointers := make([]interface{}, len(columns))
	// dynamically create list of pointers to interface to pass to row.Scan method to fetch all values
	for i := 0; i < len(columns); i++ {
		rowPointers[i] = &row[i]
	}
	var extraArgs []interface{}
	acraStructIDIndex := len(columns) - 2 // last but one item
	acraStructIndex := len(columns) - 1   // last item
	for rows.Next() {
		err = rows.Scan(rowPointers...)
		if err != nil {
			log.WithError(err).Errorln("Can't read row from result")
			return false
		}

		acraStructID, ok := row[acraStructIDIndex].([]byte)
		// check that acrastruct and id have correct types ([]byte)
		if !ok {
			log.Errorf("ClientId/ZoneId column has incorrect type (bytes expected, took %s)", reflect.TypeOf(row[acraStructIDIndex]))
			return false
		}

		acraStruct, ok := row[acraStructIndex].([]uint8)
		if !ok {
			log.Errorf("AcraStruct column has incorrect type (bytes expected, took %s)", reflect.TypeOf(row[acraStructIndex]))
			return false
		}
		logger := log.WithFields(log.Fields{"ZoneId": string(acraStructID)})
		logger.Infof("Rotate AcraStruct with ZoneId=%s", string(acraStructID))

		// rotate
		privateKey, err := keysStore.getPrivateKey(acraStructID)
		if err != nil {
			logger.WithField("acrastruct", hex.EncodeToString(acraStruct)).WithError(err).Errorln("Can't get private key")
			return false
		}
		publicKey, err := keysStore.getPublicKey(acraStructID)
		if err != nil {
			logger.WithField("acrastruct", hex.EncodeToString(acraStruct)).WithError(err).Errorln("Can't load public key")
			return false
		}
		decrypted, err := base.DecryptAcrastruct(acraStruct, privateKey, acraStructID)
		if err != nil {
			logger.WithField("acrastruct", hex.EncodeToString(acraStruct)).WithError(err).Errorln("Can't decrypt AcraStruct")
			return false
		}

		rotated, err := acrawriter.CreateAcrastruct(decrypted, publicKey, acraStructID)
		if err != nil {
			logger.WithField("acrastruct", hex.EncodeToString(acraStruct)).WithError(err).Errorln("Can't rotate data")
			return false
		}
		if len(rowPointers) > 2 {
			extraArgs = append([]interface{}{rotated}, row[:len(rowPointers)-2]...)
		} else {
			extraArgs = []interface{}{}
		}
		_, err = db.Exec(updateQuery, extraArgs...)
		if err != nil {
			logger.WithField("acrastruct", hex.EncodeToString(acraStruct)).WithError(err).Errorln("Can't update data in db via update query")
			return false
		}
	}
	jsonOutput, err := keysStore.Marshal()
	if err != nil {
		log.WithError(err).Errorln("Can't encode to json")
		return false
	}
	fmt.Println(string(jsonOutput))
	return true
}
