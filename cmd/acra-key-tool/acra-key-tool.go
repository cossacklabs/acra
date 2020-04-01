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

// Package main is entry point for acra-key-tool utility.
//
// It can access and maniplulate key stores:
//
//   - read key data
//   - destroy keys
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	keystoreV1 "github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

var (
	serviceName       = "acra-key-tool"
	defaultConfigPath = utils.GetConfigPathByName("acra-key-tool")
	defaultKeyDir     = keystoreV1.DefaultKeyDirShort
)

const (
	keyPoisonPublic   = "poison-public"
	keyPoisonPrivate  = "poison-private"
	keyStoragePublic  = "storage-public"
	keyStoragePrivate = "storage-private"
	keyZonePublic     = "zone-public"
	keyZonePrivate    = "zone-private"

	keyTransportConnector  = "transport-connector"
	keyTransportServer     = "transport-server"
	keyTransportTranslator = "transport-translator"
)

var readKeyKinds = strings.Join([]string{
	keyPoisonPublic,
	keyPoisonPrivate,
	keyStoragePublic,
	keyStoragePrivate,
	keyZonePublic,
	keyZonePrivate,
}, ", ")

var destroyKeyKinds = strings.Join([]string{
	keyTransportConnector,
	keyTransportServer,
	keyTransportTranslator,
}, ", ")

type commandLineParams struct {
	KeyStoreVersion string
	KeyDir          string
	KeyDirPublic    string

	ClientID string
	ZoneID   string

	ReadKeyKind    string
	DestroyKeyKind string
}

var params commandLineParams

func setDefaultParameterValues() {
	if params.KeyStoreVersion == "" {
		if filesystemV2.IsKeyDirectory(params.KeyDir) {
			params.KeyStoreVersion = "v2"
		} else {
			params.KeyStoreVersion = "v1"
		}
	}
	if params.KeyDirPublic == "" {
		params.KeyDirPublic = params.KeyDir
	}
}

func checkParameterConsistency() {
	if params.ClientID != "" && params.ZoneID != "" {
		log.Fatal("--client_id and --zone_id cannot be used simultaneously")
	}
	if params.ReadKeyKind != "" && params.DestroyKeyKind != "" {
		log.Fatal("--read_key and --destroy_key cannot be used simultaneously")
	}
}

func main() {
	flag.StringVar(&params.KeyStoreVersion, "keystore", "", "force key store format: v1 (current), v2 (new)")
	flag.StringVar(&params.KeyDir, "keys_dir", defaultKeyDir, "path to key directory")
	flag.StringVar(&params.KeyDirPublic, "keys_dir_public", "", "path to key directory for public keys")
	flag.StringVar(&params.ClientID, "client_id", "", "client ID for which to retrieve key")
	flag.StringVar(&params.ZoneID, "zone_id", "", "zone ID for which to retrieve key")
	flag.StringVar(&params.ReadKeyKind, "read_key", "", "key kind to read, one of: "+readKeyKinds)
	flag.StringVar(&params.DestroyKeyKind, "destroy_key", "", "key kind to destroy, one of: "+destroyKeyKinds)
	err := cmd.Parse(defaultConfigPath, serviceName)
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Fatal("Cannot parse arguments")
	}

	setDefaultParameterValues()
	checkParameterConsistency()

	if params.ReadKeyKind != "" {
		keyBytes := readKeyBytes()
		_, err = os.Stdout.Write(keyBytes)
		if err != nil {
			log.Fatalf("Failed to write key bytes: %v", err)
		}
	}

	if params.DestroyKeyKind != "" {
		destroyKey()
	}
}

func readKeyBytes() []byte {
	keyStore, err := openKeyStoreForReading()
	if err != nil {
		log.Fatalf("Failed to open key store: %v", err)
	}

	switch params.ReadKeyKind {
	case keyPoisonPublic:
		keypair, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			log.WithError(err).Fatal("Cannot read poison record key pair")
		}
		return keypair.Public.Value
	case keyPoisonPrivate:
		keypair, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			log.WithError(err).Fatal("Cannot read poison record key pair")
		}
		return keypair.Private.Value
	case keyStoragePublic:
		if params.ClientID == "" {
			log.Fatal("--key " + keyStoragePublic + " requires --client_id")
		}
		key, err := keyStore.GetClientIDEncryptionPublicKey([]byte(params.ClientID))
		if err != nil {
			log.WithError(err).Fatal("Cannot read client storage public key")
		}
		return key.Value
	case keyStoragePrivate:
		if params.ClientID == "" {
			log.Fatal("--key " + keyStoragePrivate + " requires --client_id")
		}
		key, err := keyStore.GetServerDecryptionPrivateKey([]byte(params.ClientID))
		if err != nil {
			log.WithError(err).Fatal("Cannot read client storage private key")
		}
		return key.Value
	case keyZonePublic:
		if params.ZoneID == "" {
			log.Fatal("--key " + keyZonePublic + " requires --zone_id")
		}
		key, err := keyStore.GetZonePublicKey([]byte(params.ZoneID))
		if err != nil {
			log.WithError(err).Fatal("Cannot read zone storage public key")
		}
		return key.Value
	case keyZonePrivate:
		if params.ZoneID == "" {
			log.Fatal("--key " + keyZonePrivate + " requires --zone_id")
		}
		key, err := keyStore.GetZonePrivateKey([]byte(params.ZoneID))
		if err != nil {
			log.WithError(err).Fatal("Cannot read zone storage private key")
		}
		return key.Value
	default:
		log.Fatalf("Unknown key kind: %v, allowed values: %s", params.ReadKeyKind, readKeyKinds)
		return nil
	}
}

func destroyKey() {
	keyStore, err := openKeyStoreForModification()
	if err != nil {
		log.Fatalf("Failed to open key store: %v", err)
	}

	switch params.DestroyKeyKind {
	case keyTransportConnector:
		if params.ClientID == "" {
			log.Fatal("--destroy_key " + keyTransportConnector + " requires --client_id")
		}
		err := keyStore.DestroyConnectorKeypair([]byte(params.ClientID))
		if err != nil {
			log.WithError(err).Fatal("Cannot destroy AcraConnector transport key pair")
		}
	case keyTransportServer:
		if params.ClientID == "" {
			log.Fatal("--destroy_key " + keyTransportServer + " requires --client_id")
		}
		err := keyStore.DestroyServerKeypair([]byte(params.ClientID))
		if err != nil {
			log.WithError(err).Fatal("Cannot destroy AcraServer transport key pair")
		}
	case keyTransportTranslator:
		if params.ClientID == "" {
			log.Fatal("--destroy_key " + keyTransportTranslator + " requires --client_id")
		}
		err := keyStore.DestroyTranslatorKeypair([]byte(params.ClientID))
		if err != nil {
			log.WithError(err).Fatal("Cannot destroy AcraTranslator transport key pair")
		}
	default:
		log.Fatalf("Unknown key kind: %v, allowed values: %s", params.DestroyKeyKind, destroyKeyKinds)
	}
}

func openKeyStoreForReading() (keystore.ServerKeyStore, error) {
	switch params.KeyStoreVersion {
	case "v1":
		return openKeyStoreV1()
	case "v2":
		return openKeyStoreV2()
	default:
		return nil, fmt.Errorf("unknown keystore option: %v", params.KeyStoreVersion)
	}
}

func openKeyStoreForModification() (keystore.KeyMaking, error) {
	switch params.KeyStoreVersion {
	case "v1":
		return openKeyStoreV1()
	case "v2":
		return openKeyStoreV2()
	default:
		return nil, fmt.Errorf("unknown keystore option: %v", params.KeyStoreVersion)
	}
}

func openKeyStoreV1() (*filesystem.KeyStore, error) {
	symmetricKey, err := keystore.GetMasterKeyFromEnvironment()
	if err != nil {
		log.WithError(err).Errorln("Cannot read master keys from environment")
		return nil, err
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(symmetricKey)
	if err != nil {
		log.WithError(err).Errorln("Failed to initialize Secure Cell encryptor")
		return nil, err
	}
	var store *filesystem.KeyStore
	if params.KeyDir != params.KeyDirPublic {
		store, err = filesystem.NewFilesystemKeyStoreTwoPath(params.KeyDir, params.KeyDirPublic, scellEncryptor)
	} else {
		store, err = filesystem.NewFilesystemKeyStore(params.KeyDir, scellEncryptor)
	}
	if err != nil {
		log.WithError(err).Errorln("Failed to initialize key")
		return nil, err
	}
	return store, nil
}

func openKeyStoreV2() (*keystoreV2.ServerKeyStore, error) {
	encryption, signature, err := keystoreV2.GetMasterKeysFromEnvironment()
	if err != nil {
		log.WithError(err).Error("Cannot read master keys from environment")
		return nil, err
	}
	suite, err := keystoreV2.NewSCellSuite(encryption, signature)
	if err != nil {
		log.WithError(err).Error("Failed to initialize Secure Cell crypto suite")
		return nil, err
	}
	keyDir, err := filesystemV2.OpenDirectoryRW(params.KeyDir, suite)
	if err != nil {
		log.WithError(err).WithField("path", params.KeyDir).Error("Cannot open key directory")
		return nil, err
	}
	return keystoreV2.NewServerKeyStore(keyDir), nil
}
