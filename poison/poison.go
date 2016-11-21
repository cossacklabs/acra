package poison

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/cossacklabs/acra"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/message"
	"io/ioutil"
	"log"
	math_rand "math/rand"
	"os"
	"time"
)

const (
	DEFAULT_POISON_KEY_PATH = "~/.ssession/poison_key"
	DEFAULT_DATA_LENGTH     = -1
	MAX_DATA_LENGTH         = 100
)

func GeneratePoisonKey(path string) ([]byte, error) {
	key := make([]byte, acra.SYMMETRIC_KEY_SIZE)
	n, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	if n != acra.SYMMETRIC_KEY_SIZE {
		return nil, errors.New("Can't generate random key of correct length")
	}

	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	n, err = file.Write(key)
	if n != acra.SYMMETRIC_KEY_SIZE {
		return nil, errors.New("Error in writing poison key")
	}
	if err != nil {
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

	encrypted_data_length := make([]byte, acra.DATA_LENGTH_SIZE)
	binary.LittleEndian.PutUint64(encrypted_data_length, uint64(len(encrypted_data)))
	output := make([]byte, len(acra.TAG_BEGIN)+acra.KEY_BLOCK_LENGTH+acra.DATA_LENGTH_SIZE+len(encrypted_data))
	output = append(output[:0], acra.TAG_BEGIN...)
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
	if _, err = os.Stat(path); os.IsNotExist(err) {
		log.Printf("Error: %v\n", utils.ErrorMessage("can't check is exists poison key in fs", err))
		key, err := GeneratePoisonKey(path)
		if err != nil {
			return nil, err
		}
		err = ioutil.WriteFile(path, key, 0600)
		if err != nil {
			return nil, err
		}
		return key, nil
	} else {
		return ioutil.ReadFile(path)
	}
}
