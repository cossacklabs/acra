// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package poison

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/message"
	"io/ioutil"
	"log"
	math_rand "math/rand"
	"os"
	"path/filepath"
	"time"
)

const (
	DEFAULT_POISON_KEY_PATH = ".acrakeys/poison_key"
	DEFAULT_DATA_LENGTH     = -1
	MAX_DATA_LENGTH         = 100
)

func GeneratePoisonKey(path string) ([]byte, error) {
	key := make([]byte, base.SYMMETRIC_KEY_SIZE)
	n, err := rand.Read(key)
	if err != nil {
		return nil, errors.New("Can't generate random key of correct length")
		return nil, err
	}
	if n != base.SYMMETRIC_KEY_SIZE {
		return nil, errors.New("Can't generate random key of correct length")
	}

	err = ioutil.WriteFile(path, key, 0600)
	if err != nil {
		log.Println("Error: can't write poison key to file")
		return nil, err
	}
	return key, nil
}

func CreatePoisonRecord(poison_key []byte, data_length int, acra_public *keys.PublicKey) ([]byte, error) {
	// data length can't be zero
	if data_length == DEFAULT_DATA_LENGTH {
		math_rand.Seed(time.Now().UnixNano())
		// from 1 to MAX_DATA_LENGTH
		data_length = 1 + int(math_rand.Int31n(MAX_DATA_LENGTH-1))
	}
	random_kp, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		return nil, err
	}
	// create smessage for encrypting symmetric key
	smessage := message.New(random_kp.Private, acra_public)
	encrypted_key, err := smessage.Wrap(poison_key)
	if err != nil {
		return nil, err
	}

	// +1 for excluding 0
	data := make([]byte, data_length)
	_, err = rand.Read(data)
	if err != nil {
		return nil, err
	}
	// create scell for encrypting data
	scell := cell.New(poison_key, cell.CELL_MODE_SEAL)
	encrypted_data, _, err := scell.Protect(data, nil)
	if err != nil {
		return nil, err
	}

	encrypted_data_length := make([]byte, base.DATA_LENGTH_SIZE)
	binary.LittleEndian.PutUint64(encrypted_data_length, uint64(len(encrypted_data)))
	output := make([]byte, len(base.TAG_BEGIN)+base.KEY_BLOCK_LENGTH+base.DATA_LENGTH_SIZE+len(encrypted_data))
	output = append(output[:0], base.TAG_BEGIN...)
	output = append(output, random_kp.Public.Value...)
	output = append(output, encrypted_key...)
	output = append(output, encrypted_data_length...)
	output = append(output, encrypted_data...)
	return output, nil
}

func GetOrCreatePoisonKey(path string) ([]byte, error) {
	path, err := utils.AbsPath(path)
	if err != nil {
		return nil, err
	}
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		dir := filepath.Dir(path)
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			log.Printf("Error: %v\n", utils.ErrorMessage("can't create directory for poison key", err))
			return nil, err
		}
		key, err := GeneratePoisonKey(path)
		if err != nil {
			log.Printf("Error: %v\n", utils.ErrorMessage("can't generate poison key", err))
			return nil, err
		}
		return key, nil
	} else if err != nil {
		log.Printf("Error: %v\n", utils.ErrorMessage("can't check existence of poison key path", err))
		return nil, err
	} else {
		return ioutil.ReadFile(path)
	}
}
