/*
Copyright 2020, Cossack Labs Limited

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

package masking

import (
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/masking/common"
	"github.com/cossacklabs/themis/gothemis/keys"
)

// Masker interface for masking/unmasking data
type Masker interface {
	Mask(data []byte, dataManipulator DataManipulator, plaintextLength int, side common.PlainTextSide) ([]byte, error)
	Unmask(data []byte, dataManipulator DataManipulator, plaintextLength int, maskingPattern []byte, side common.PlainTextSide) ([]byte, error)
}

// KeyStore interface with required methods from keystore for masking
type KeyStore interface {
	keystore.PublicKeyStore
	GetServerDecryptionPrivateKeys(id []byte) ([]*keys.PrivateKey, error)
}
type masker struct {
	keystore KeyStore
}

// NewMasker return new Masker
func NewMasker(keystore KeyStore) (Masker, error) {
	return &masker{keystore: keystore}, nil
}

// DataManipulator interface for component which do something with data and return changed
type DataManipulator interface {
	ChangeData([]byte) ([]byte, error)
	UnchangeData([]byte) ([]byte, error)
}

// Unmask data or return masked with maskingPattern instead acrastruct
func (m *masker) Unmask(data []byte, dataManipulator DataManipulator, plaintextLength int, maskingPattern []byte, side common.PlainTextSide) ([]byte, error) {
	if plaintextLength > len(data) {
		return data, nil
	}
	var result []byte
	if side == common.PlainTextSideLeft {
		partialPlaintext := data[0:plaintextLength]
		changedData, err := dataManipulator.UnchangeData(data[plaintextLength:])
		if err != nil {
			return append(partialPlaintext, maskingPattern...), err
		}
		result = append(partialPlaintext, changedData...)
	} else {
		partialPlaintext := data[len(data)-plaintextLength:]
		changedData, err := dataManipulator.UnchangeData(data[0 : len(data)-plaintextLength])
		if err != nil {
			return append(maskingPattern, partialPlaintext...), err
		}
		result = append(changedData, partialPlaintext...)
	}
	return result, nil
}

// Mask data, leave plaintext with plaintextLength length of raw data and encrypt with acrastruct other piece of data
func (m *masker) Mask(data []byte, dataManipulator DataManipulator, plaintextLength int, side common.PlainTextSide) ([]byte, error) {
	if plaintextLength > len(data) {
		return data, nil
	}
	var result []byte
	if side == common.PlainTextSideLeft {
		partialPlaintext := data[0:plaintextLength]
		changedData, err := dataManipulator.ChangeData(data[plaintextLength:])
		if err != nil {
			return nil, err
		}
		result = append(partialPlaintext, changedData...)
	} else {
		partialPlaintext := data[len(data)-plaintextLength:]
		changedData, err := dataManipulator.ChangeData(data[0 : len(data)-plaintextLength])
		if err != nil {
			return nil, err
		}
		result = append(changedData, partialPlaintext...)
	}
	return result, nil
}
