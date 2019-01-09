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

package postgresql

import (
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/zone"
)

// EscapeType store type of escape methods for binary data
type EscapeType int8

// Possible bytea formats
const (
	HexByteaFormat    EscapeType = 1
	EscapeByteaFormat EscapeType = 2
)

type dataDecryptorFactoryMethod func() base.DataDecryptor
type matcherPoolFactoryMethod func() *zone.MatcherPool

// DecryptorFactory to create new decryptors for postgresql
type DecryptorFactory struct {
	settings           *base.DecryptorSetting
	decryptorFactory   dataDecryptorFactoryMethod
	zoneMatcherFactory matcherPoolFactoryMethod
}

// NewDecryptorFactory return new DecryptorFactory
func NewDecryptorFactory(byteFormat EscapeType, setting *base.DecryptorSetting) *DecryptorFactory {
	var dataDecryptor dataDecryptorFactoryMethod
	var matcherPool matcherPoolFactoryMethod
	if byteFormat == HexByteaFormat {
		dataDecryptor = func() base.DataDecryptor {
			return NewPgHexDecryptor()
		}
		matcherPool = func() *zone.MatcherPool {
			return zone.NewMatcherPool(zone.NewPgHexMatcherFactory())
		}
	} else if byteFormat == EscapeByteaFormat {
		dataDecryptor = func() base.DataDecryptor {
			return NewPgEscapeDecryptor()
		}
		matcherPool = func() *zone.MatcherPool {
			return zone.NewMatcherPool(zone.NewPgEscapeMatcherFactory())
		}
	}
	return &DecryptorFactory{
		decryptorFactory:   dataDecryptor,
		zoneMatcherFactory: matcherPool,
		settings:           setting,
	}
}

// New return new initialized decryptor for postgresql
func (fabric *DecryptorFactory) New(clientID []byte) (base.Decryptor, error) {
	dataDecryptor := fabric.decryptorFactory()
	matcherPool := fabric.zoneMatcherFactory()
	decryptor := NewPgDecryptor(clientID, dataDecryptor, fabric.settings.WithZone(), fabric.settings.Keystore())
	decryptor.isWholeMatch = fabric.settings.WholeMatch()
	zoneMatcher := zone.NewZoneMatcher(matcherPool, fabric.settings.Keystore())
	decryptor.zoneMatcher = zoneMatcher
	decryptor.callbackStorage = fabric.settings.PoisonCallbacks()
	decryptor.checkPoisonRecords = fabric.settings.CheckPoisonRecord()
	decryptor.dataProcessor = NewEncodeDecodeWrapper(base.DecryptProcessor{})
	return decryptor, nil
}
