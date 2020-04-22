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

package keys

import (
	"github.com/cossacklabs/acra/keystore"
	log "github.com/sirupsen/logrus"
)

// SupportedDestroyKeyKinds is a list of keys supported by `destroy-key` subcommand.
var SupportedDestroyKeyKinds = []string{
	KeyTransportConnector,
	KeyTransportServer,
	KeyTransportTranslator,
}

// DestroyKey destroys data of the requsted key.
func DestroyKey(params *CommandLineParams, keyStore keystore.KeyMaking) error {
	switch params.DestroyKeyKind {
	case KeyTransportConnector:
		err := keyStore.DestroyConnectorKeypair([]byte(params.ClientID))
		if err != nil {
			log.WithError(err).Error("Cannot destroy AcraConnector transport key pair")
			return err
		}
		return nil

	case KeyTransportServer:
		err := keyStore.DestroyServerKeypair([]byte(params.ClientID))
		if err != nil {
			log.WithError(err).Error("Cannot destroy AcraServer transport key pair")
			return err
		}
		return nil

	case KeyTransportTranslator:
		err := keyStore.DestroyTranslatorKeypair([]byte(params.ClientID))
		if err != nil {
			log.WithError(err).Error("Cannot destroy AcraTranslator transport key pair")
			return err
		}
		return nil

	default:
		log.WithField("expected", SupportedDestroyKeyKinds).
			Errorf("Unknown key kind: %s", Params.ReadKeyKind)
		return ErrUnknownKeyKind
	}
}
