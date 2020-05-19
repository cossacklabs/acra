/*
 * Copyright 2020, Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package keystore implements Acra Key Store version 2.
package keystore

import (
	connector_mode "github.com/cossacklabs/acra/cmd/acra-connector/connector-mode"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	log "github.com/sirupsen/logrus"
)

const serviceName = "keystore"

// ServerKeyStore provides full access to Acra Key Store.
//
// It is intended to be used by AcraServer components and uses server transport keys.
type ServerKeyStore struct {
	api.MutableKeyStore
	log *log.Entry
}

// ConnectorKeyStore provides access to Acra Key Store for AcraConnector.
//
// This is the same as ServerKeyStore, but with AcraConnector transport keys.
type ConnectorKeyStore struct {
	ServerKeyStore
	clientID []byte
	mode     connector_mode.ConnectorMode
}

// TranslatorKeyStore provides access to Acra Key Store for AcraTranslator.
//
// This is the same as ServerKeyStore, but with AcraTranslator transport keys.
type TranslatorKeyStore struct {
	ServerKeyStore
}

// NewServerKeyStore configures key store for AcraServer.
func NewServerKeyStore(keyStore api.MutableKeyStore) *ServerKeyStore {
	return &ServerKeyStore{keyStore, log.WithField("service", serviceName)}
}

// NewConnectorKeyStore configures key store for AcraConnector.
// Aside from key store you need to provide connecting clientID and connection mode.
func NewConnectorKeyStore(keyStore api.MutableKeyStore, clientID []byte, mode connector_mode.ConnectorMode) *ConnectorKeyStore {
	return &ConnectorKeyStore{
		ServerKeyStore: ServerKeyStore{keyStore, log.WithField("service", serviceName)},
		clientID:       clientID,
		mode:           mode,
	}
}

// NewTranslatorKeyStore configures key store for AcraTranslator
func NewTranslatorKeyStore(keyStore api.MutableKeyStore) *TranslatorKeyStore {
	return &TranslatorKeyStore{
		ServerKeyStore{keyStore, log.WithField("service", serviceName)},
	}
}

// ListKeys enumerates keys present in the key store.
func (s *ServerKeyStore) ListKeys() ([]keystore.KeyDescription, error) {
	panic("not implemented")
}

// Reset is a compatibility method that does nothing.
// In KeyStoreV1 this method is used to reset cache.
// KeyStoreV2 currently does not support key caching so there is nothing to reset.
func (s *ServerKeyStore) Reset() {
}
