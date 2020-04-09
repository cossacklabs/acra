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
	"errors"

	"github.com/cossacklabs/acra/keystore"
	log "github.com/sirupsen/logrus"
)

// SupportedReadKeyKinds is a list of keys supported by `read-key` subcommand.
var SupportedReadKeyKinds = []string{
	KeyPoisonPublic,
	KeyPoisonPrivate,
	KeyStoragePublic,
	KeyStoragePrivate,
	KeyZonePublic,
	KeyZonePrivate,
}

// Key parameter errors:
var (
	ErrMissingClientID = errors.New("client ID not specified")
	ErrMissingZoneID   = errors.New("zone ID not specified")
	ErrUnknownKeyKind  = errors.New("unknown key kind")
)

// ReadKeyBytes returns plaintext bytes of the requsted key.
func ReadKeyBytes(params *CommandLineParams, keyStore keystore.ServerKeyStore) ([]byte, error) {
	switch params.ReadKeyKind {
	case KeyPoisonPublic:
		keypair, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			log.WithError(err).Error("Cannot read poison record key pair")
			return nil, err
		}
		return keypair.Public.Value, nil

	case KeyPoisonPrivate:
		keypair, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			log.WithError(err).Error("Cannot read poison record key pair")
			return nil, err
		}
		return keypair.Private.Value, nil

	case KeyStoragePublic:
		if Params.ClientID == "" {
			log.Error("--key " + KeyStoragePublic + " requires --client_id")
			return nil, ErrMissingClientID
		}
		key, err := keyStore.GetClientIDEncryptionPublicKey([]byte(Params.ClientID))
		if err != nil {
			log.WithError(err).Error("Cannot read client storage public key")
			return nil, err
		}
		return key.Value, nil

	case KeyStoragePrivate:
		if Params.ClientID == "" {
			log.Error("--key " + KeyStoragePrivate + " requires --client_id")
			return nil, ErrMissingClientID
		}
		key, err := keyStore.GetServerDecryptionPrivateKey([]byte(Params.ClientID))
		if err != nil {
			log.WithError(err).Error("Cannot read client storage private key")
			return nil, err
		}
		return key.Value, nil

	case KeyZonePublic:
		if Params.ZoneID == "" {
			log.Error("--key " + KeyZonePublic + " requires --zone_id")
			return nil, ErrMissingZoneID
		}
		key, err := keyStore.GetZonePublicKey([]byte(Params.ZoneID))
		if err != nil {
			log.WithError(err).Error("Cannot read zone storage public key")
			return nil, err
		}
		return key.Value, nil

	case KeyZonePrivate:
		if Params.ZoneID == "" {
			log.Error("--key " + KeyZonePrivate + " requires --zone_id")
			return nil, ErrMissingZoneID
		}
		key, err := keyStore.GetZonePrivateKey([]byte(Params.ZoneID))
		if err != nil {
			log.WithError(err).Error("Cannot read zone storage private key")
			return nil, err
		}
		return key.Value, nil

	default:
		log.WithField("expected", SupportedReadKeyKinds).
			Errorf("Unknown key kind: %s", Params.ReadKeyKind)
		return nil, ErrUnknownKeyKind
	}
}
