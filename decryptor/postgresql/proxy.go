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
	"context"
	"errors"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"net"
)

type proxyFactory struct {
	setting base.ProxySetting
}

// NewProxyFactory return new proxyFactory
func NewProxyFactory(proxySetting base.ProxySetting) (base.ProxyFactory, error) {
	return &proxyFactory{
		setting: proxySetting,
	}, nil
}

// New return postgresql proxy implementation
func (factory *proxyFactory) New(ctx context.Context, clientID []byte, dbConnection, clientConnection net.Conn) (base.Proxy, error) {
	decryptor, err := factory.setting.DecryptorFactory().New(clientID)
	if err != nil {
		return nil, err
	}
	decryptor.SetDataProcessor(base.DecryptProcessor{})
	proxy, err := NewPgProxy(ctx, decryptor, dbConnection, clientConnection, factory.setting.TLSConfig(), factory.setting.Censor())
	if err != nil {
		return nil, err
	}

	if !factory.setting.TableSchemaStore().IsEmpty() {
		dataEncryptor, err := encryptor.NewAcrawriterDataEncryptor(factory.setting.KeyStore())
		if err != nil {
			return nil, err
		}
		queryEncryptor, err := encryptor.NewPostgresqlQueryEncryptor(factory.setting.TableSchemaStore(), clientID, dataEncryptor)
		if err != nil {
			return nil, err
		}
		proxy.AddQueryObserver(queryEncryptor)
	}
	notifier, ok := decryptor.(base.DecryptionSubscriber)
	if !ok {
		return nil, errors.New("decryptor doesn't implement DecryptionSubscriber interface")
	}
	proxy.SubscribeOnAllColumnsDecryption(notifier)

	return proxy, nil
}
