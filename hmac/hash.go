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

package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
)

type funcNumber uint8

// Hash provide methods to work with known hash signature
type Hash interface {
	IsEqual(data []byte, keyID []byte, keystore keystore.HmacKeyStore) bool
	Marshal() []byte
	Length() int
}

const (
	// 127..255 numbers to avoid using 7-bit ASCII chars and low integer values to reduce false match of hash signatures
	_sha256 = funcNumber(255/2 + iota)
)

var hashFuncMap = map[funcNumber]func() hash.Hash{
	_sha256: sha256.New,
}

const defaultFuncNumber = _sha256

// GetDefaultHashSize return size of hash signature with hash func number prefix
func GetDefaultHashSize() int {
	return hashFuncMap[defaultFuncNumber]().Size() + 1
}

// GenerateHMAC return hmac with default hash function
func GenerateHMAC(key, data []byte) []byte {
	h := hmac.New(hashFuncMap[defaultFuncNumber], key)
	h.Write(data)
	mac := h.Sum(nil)
	utils.ZeroizeSymmetricKey(key)
	h.Reset()
	return append([]byte{uint8(defaultFuncNumber)}, mac...)
}

// HashData implementation of Hash interface
type HashData struct {
	info func() hash.Hash
	data []byte
}

// Marshal hash digest
func (d *HashData) Marshal() []byte { return d.data }

// Length of hash data
func (d *HashData) Length() int { return len(d.data) }

// IsEqual if hmac equal to calculated hmac for data
func (d *HashData) IsEqual(data []byte, keyID []byte, store keystore.HmacKeyStore) bool {
	key, err := store.GetHMACSecretKey(keyID)
	if err != nil {
		return false
	}
	h := hmac.New(d.info, key)
	h.Write(data)
	mac := h.Sum(nil)
	h.Reset()
	utils.ZeroizeSymmetricKey(key)
	return hmac.Equal(d.data[1:], mac)
}

// ExtractHash return Hash if matched otherwise nil
func ExtractHash(data []byte) Hash {
	if len(data) == 0 {
		return nil
	}
	hashFunc, ok := hashFuncMap[funcNumber(data[0])]
	if !ok {
		logrus.Debugln("Unknown hash function")
		return nil
	}
	size := hashFunc().Size()
	if len(data[1:]) < size {
		logrus.Debugln("Data has less length that need")
		return nil
	}
	logrus.Debugln("Return without hash")
	return &HashData{info: hashFunc, data: data[:size+1]}
}

// ExtractHashAndData return hash and data with extracted hash if matched. Otherwise both are nil
func ExtractHashAndData(container []byte) (Hash, []byte) {
	hashData := ExtractHash(container)
	if hashData == nil {
		return nil, nil
	}
	return hashData, container[hashData.Length():]
}

// NewDefaultHash return hash wrapper from raw hash data
func NewDefaultHash(rawHashData []byte) *HashData {
	return &HashData{info: hashFuncMap[defaultFuncNumber], data: append([]byte{uint8(defaultFuncNumber)}, rawHashData...)}
}
