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
	"fmt"
	"reflect"

	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

// rotateDb execute selectQuery to fetch AcraStructs with related zone ids, decrypt with rotated zone keys and
func rotateDb(selectQuery, updateQuery string, db *sql.DB, keystore RotateStorageKeyStore, encoder utils.BinaryEncoder, zoneMode, dryRun bool) bool {
	rotator, err := newRotator(keystore, zoneMode)
	if err != nil {
		return false
	}
	defer rotator.clearKeys()

	rows, err := db.Query(selectQuery)
	if err != nil {
		log.WithError(err).Errorf("Can't fetch result with sql_select query")
		return false
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		log.WithError(err).Errorln("Can't fetch metadata for result columns")
		return false
	}
	if len(columns) < 2 {
		log.Errorln("Result has < 2 columns. Expected at least ZoneId and AcraStruct")
		return false
	}

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
		logger := log.WithFields(log.Fields{"Key ID": string(acraStructID)})
		logger.Infof("Rotate AcraStruct")

		// rotate
		rotated, err := rotator.rotateAcrastruct(acraStructID, acraStruct)
		if err != nil {
			logger.WithField("acrastruct", hex.EncodeToString(acraStruct)).WithError(err).Errorln("Can't rotate data")
			return false
		}

		rotatedStr := encoder.Encode(rotated)
		if len(rowPointers) > 2 {
			extraArgs = append([]interface{}{rotatedStr}, row[:len(rowPointers)-2]...)
		} else {
			extraArgs = []interface{}{rotatedStr}
		}
		if !dryRun {
			_, err = db.Exec(updateQuery, extraArgs...)
			if err != nil {
				logger.WithError(err).Errorln("Can't update data in db via sql_update query")
				return false
			}
		}
	}
	if !dryRun {
		if err = rotator.saveRotatedKeys(); err != nil {
			log.WithError(err).Errorln("Can't save rotated keys")
			return false
		}
	}
	jsonOutput, err := rotator.marshal()
	if err != nil {
		log.WithError(err).Errorln("Can't encode to json")
		return false
	}
	fmt.Println(string(jsonOutput))
	return true
}
