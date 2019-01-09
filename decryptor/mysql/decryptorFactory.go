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

package mysql

import (
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/postgresql"
)

// DecryptorFactory implement DecryptorFactory for mysql
type DecryptorFactory struct {
	settings           *base.DecryptorSetting
	pgDecryptorFactory *postgresql.DecryptorFactory
}

// NewMysqlDecryptorFactory return DecryptorFactory for mysql
func NewMysqlDecryptorFactory(setting *base.DecryptorSetting) *DecryptorFactory {
	// no matter which escape type to use
	pgFactory := postgresql.NewDecryptorFactory(postgresql.HexByteaFormat, setting)
	return &DecryptorFactory{settings: setting, pgDecryptorFactory: pgFactory}
}

// New return new Decryptor
func (factory *DecryptorFactory) New(clientID []byte) (base.Decryptor, error) {
	pgDecryptor, err := factory.pgDecryptorFactory.New(clientID)
	if err != nil {
		return nil, err
	}
	decryptor := NewMySQLDecryptor(clientID, pgDecryptor.(*postgresql.PgDecryptor), factory.settings.Keystore())
	decryptor.SetPoisonCallbackStorage(factory.settings.PoisonCallbacks())
	decryptor.SetWithZone(factory.settings.WithZone())
	decryptor.SetWholeMatch(factory.settings.WholeMatch())
	decryptor.TurnOnPoisonRecordCheck(factory.settings.CheckPoisonRecord())
	decryptor.SetDataProcessor(base.DecryptProcessor{})
	return decryptor, nil
}
