/*
Copyright 2016, Cossack Labs Limited

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

// Package main is entry point for AcraKeymaker utility. AcraKeymaker generates key pairs for transport and storage keys
// and writes it to default keys folder. Private keys are encrypted using Themis SecureCell and ACRA_MASTER_KEY,
// public keys are plaintext.
//
// https://github.com/cossacklabs/acra/wiki/Key-Management
package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/cossacklabs/acra/network"
	"io/ioutil"
	"os"
	"strings"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/keystore/keyloader/hashicorp"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	filesystemBackendV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"

	log "github.com/sirupsen/logrus"
)

// Constants used by AcraKeymaker
var (
	// DefaultConfigPath relative path to config which will be parsed as default
	DefaultConfigPath = utils.GetConfigPathByName("acra-keymaker")
	ServiceName       = "acra-keymaker"
)

func main() {
	clientID := flag.String("client_id", "client", "Client ID")
	acraConnector := flag.Bool("generate_acraconnector_keys", false, "Create keypair for AcraConnector only")
	acraServer := flag.Bool("generate_acraserver_keys", false, "Create keypair for AcraServer only")
	acraTranslator := flag.Bool("generate_acratranslator_keys", false, "Create keypair for AcraTranslator only")
	dataKeys := flag.Bool("generate_acrawriter_keys", false, "Create keypair for data encryption/decryption")
	basicauth := flag.Bool("generate_acrawebconfig_keys", false, "Create symmetric key for AcraWebconfig's basic auth db")
	outputDir := flag.String("keys_output_dir", keystore.DefaultKeyDirShort, "Folder where will be saved keys")
	outputPublicKey := flag.String("keys_public_output_dir", keystore.DefaultKeyDirShort, "Folder where will be saved public key")
	hmac := flag.Bool("generate_hmac_key", false, "Create key for HMAC calculation")
	logKey := flag.Bool("generate_log_key", false, "Create key for log integrity checks")
	symStorageKey := flag.Bool("generate_symmetric_storage_key", false, "Generate symmetric key for data encryption/decryption with AcraBlock")
	masterKey := flag.String("generate_master_key", "", "Generate new random master key and save to file")
	poisonRecord := flag.Bool("generate_poisonrecord_keys", false, "Generate keypair and symmetric key for poison records")
	cmd.RegisterRedisKeyStoreParameters()
	keystoreVersion := flag.String("keystore", "", "set keystore format: v1 (current), v2 (new)")

	tlsClientCert := flag.String("tls_cert", "", "Path to TLS certificate to use as client_id identifier")
	tlsIdentifierExtractorType := flag.String("tls_identifier_extractor_type", network.IdentifierExtractorTypeDistinguishedName, fmt.Sprintf("Decide which field of TLS certificate to use as ClientID (%s). Default is %s.", strings.Join(network.IdentifierExtractorTypesList, "|"), network.IdentifierExtractorTypeDistinguishedName))

	hashicorp.RegisterVaultCLIParameters()
	logging.SetLogLevel(logging.LogVerbose)

	err := cmd.Parse(DefaultConfigPath, ServiceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}
	if len(*clientID) != 0 && *tlsClientCert != "" {
		log.Errorln("You can either specify identifier for keys via specific clientID by --client_id parameter or via TLS certificate by --tls_cert parameter.")
		os.Exit(1)
	}
	if len(*clientID) == 0 && *tlsClientCert != "" {
		idConverter, err := network.NewDefaultHexIdentifierConverter()
		if err != nil {
			log.WithError(err).Errorln("Can't initialize identifier converter")
			os.Exit(1)
		}
		identifierExtractor, err := network.NewIdentifierExtractorByType(*tlsIdentifierExtractorType)
		if err != nil {
			log.WithField("type", *tlsIdentifierExtractorType).WithError(err).Errorln("Can't initialize identifier extractor")
			os.Exit(1)
		}
		clientIDExtractor, err := network.NewTLSClientIDExtractor(identifierExtractor, idConverter)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize clientID extractor")
			os.Exit(1)
		}
		pemCertificateFile, err := ioutil.ReadFile(*tlsClientCert)
		if err != nil {
			log.WithError(err).Errorln("Can't read TLS certificate")
			os.Exit(1)
		}
		block, _ := pem.Decode(pemCertificateFile)
		if block == nil {
			log.WithError(err).Errorln("Can't parse TLS certificate as PEM encoded file")
			os.Exit(1)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.WithError(err).Errorln("Can't parse TLS certificate")
			os.Exit(1)
		}
		tlsClientID, err := clientIDExtractor.ExtractClientID(certificate)
		if err != nil {
			log.WithError(err).Errorln("Can't extract clientID from TLS certificate")
			os.Exit(1)
		}
		*clientID = string(tlsClientID)
	}

	cmd.ValidateClientID(*clientID)

	if *masterKey != "" {
		var newKey []byte
		switch *keystoreVersion {
		case "v1":
			newKey, err = keystore.GenerateSymmetricKey()
		case "v2":
			newKey, err = keystoreV2.NewSerializedMasterKeys()
		case "":
			log.Errorf("Keystore version is required: --keystore={v1|v2}")
			os.Exit(1)
		default:
			log.Errorf("Unknown --keystore option: %v", *keystoreVersion)
			os.Exit(1)
		}
		if err != nil {
			log.WithError(err).Errorln("Failed to generate master key")
			os.Exit(1)
		}
		if err := ioutil.WriteFile(*masterKey, newKey, 0600); err != nil {
			log.WithError(err).WithField("path", *masterKey).Errorln("Failed to write master key")
			os.Exit(1)
		}
		os.Exit(0)
	}

	var store keystore.KeyMaking
	// If the keystore already exists, detect its version automatically and allow to not specify it.
	if *keystoreVersion == "" {
		if filesystemV2.IsKeyDirectory(*outputDir) {
			*keystoreVersion = "v2"
		} else if filesystem.IsKeyDirectory(*outputDir) {
			*keystoreVersion = "v1"
		}
	}

	keyLoader, err := keyloader.GetInitializedMasterKeyLoader(hashicorp.GetVaultCLIParameters())
	if err != nil {
		log.WithError(err).Errorln("Can't initialize ACRA_MASTER_KEY loader")
		os.Exit(1)
	}

	switch *keystoreVersion {
	case "v1":
		store = openKeyStoreV1(*outputDir, *outputPublicKey, keyLoader)
	case "v2":
		store = openKeyStoreV2(*outputDir, keyLoader)
	case "":
		log.Errorf("Keystore version is required: --keystore={v1|v2}")
		os.Exit(1)
	default:
		log.Errorf("Unknown --keystore version: %v (supported: v1, v2)", *keystoreVersion)
		os.Exit(1)
	}

	if *poisonRecord {
		// Generate poison record symmetric key
		if err = store.GeneratePoisonRecordSymmetricKey(); err != nil {
			panic(err)
		}
		fmt.Println("Generated symmetric key for poison records")
		// Generate poison record keypair
		if _, err = store.GetPoisonKeyPair(); err != nil {
			panic(err)
		}
		fmt.Println("Generated keypair for poison records")
	}

	if *acraConnector {
		err = store.GenerateConnectorKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated acra-connector keypair")
	}
	if *acraServer {
		err = store.GenerateServerKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated acra-server keypair")
	}
	if *acraTranslator {
		err = store.GenerateTranslatorKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated acra-translator keypair")
	}
	if *dataKeys {
		err = store.GenerateDataEncryptionKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated storage encryption keypair")
	}
	if *basicauth {
		_, err = store.GetAuthKey(true)
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated key for basic auth for acra-webconfig")
	}
	if *hmac {
		err = store.GenerateHmacKey([]byte(*clientID))
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated HMAC key for searchable encryption")
	}
	if *symStorageKey {
		err = store.GenerateClientIDSymmetricKey([]byte(*clientID))
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated storage symmetric key for clientID")
	}
	if *logKey {
		err = store.GenerateLogKey()
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated HMAC key for secure logging")
	}

	if !(*acraConnector || *acraServer || *acraTranslator || *dataKeys || *basicauth || *hmac || *poisonRecord || *symStorageKey || *logKey) {
		err = store.GenerateConnectorKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated acra-connector keypair")

		err = store.GenerateServerKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated acra-server keypair")

		err = store.GenerateTranslatorKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated acra-translator keypair")

		err = store.GenerateDataEncryptionKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated storage encryption keypair")
		_, err = store.GetAuthKey(true)
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated key for basic auth for acra-webconfig")
		err = store.GenerateHmacKey([]byte(*clientID))
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated HMAC key for searchable encryption")
		err = store.GenerateLogKey()
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated HMAC key for secure logging")
		err = store.GenerateClientIDSymmetricKey([]byte(*clientID))
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated storage symmetric key for clientID")
		// Generate poison record symmetric key
		if err = store.GeneratePoisonRecordSymmetricKey(); err != nil {
			panic(err)
		}
		fmt.Println("Generated symmetric key for poison records")
		// Generate poison record keypair
		if _, err = store.GetPoisonKeyPair(); err != nil {
			panic(err)
		}
		fmt.Println("Generated keypair for poison records")
	}
}

func openKeyStoreV1(output, outputPublic string, loader keyloader.MasterKeyLoader) keystore.KeyMaking {
	masterKey, err := loader.LoadMasterKey()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master key")
		os.Exit(1)
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithError(err).Errorln("Can't init scell encryptor")
		os.Exit(1)
	}
	keyStore := filesystem.NewCustomFilesystemKeyStore()
	if outputPublic != output {
		keyStore.KeyDirectories(output, outputPublic)
	} else {
		keyStore.KeyDirectory(output)
	}
	keyStore.Encryptor(scellEncryptor)
	redis := cmd.GetRedisParameters()
	if redis.KeysConfigured() {
		keyStorage, err := filesystem.NewRedisStorage(redis.HostPort, redis.Password, redis.DBKeys, nil)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
				Errorln("Can't initialize Redis client")
			os.Exit(1)
		}
		keyStore.Storage(keyStorage)
	}
	keyStoreV1, err := keyStore.Build()
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore")
		os.Exit(1)
	}
	return keyStoreV1
}

func openKeyStoreV2(keyDirPath string, loader keyloader.MasterKeyLoader) keystore.KeyMaking {
	encryption, signature, err := loader.LoadMasterKeys()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master key")
		os.Exit(1)
	}
	suite, err := keystoreV2.NewSCellSuite(encryption, signature)
	if err != nil {
		log.WithError(err).Error("Failed to initialize Secure Cell crypto suite")
		os.Exit(1)
	}
	var backend filesystemBackendV2.Backend
	redis := cmd.GetRedisParameters()
	if redis.KeysConfigured() {
		config := &filesystemBackendV2.RedisConfig{
			RootDir: keyDirPath,
			Options: redis.KeysOptions(),
		}
		backend, err = filesystemBackendV2.CreateRedisBackend(config)
		if err != nil {
			log.WithError(err).Error("Cannot connect to Redis keystore")
			os.Exit(1)
		}
	} else {
		backend, err = filesystemBackendV2.CreateDirectoryBackend(keyDirPath)
		if err != nil {
			log.WithError(err).Error("Cannot open key directory")
			os.Exit(1)
		}
	}
	keyDirectory, err := filesystemV2.CustomKeyStore(backend, suite)
	if err != nil {
		log.WithError(err).Error("Failed to initialize key directory")
		os.Exit(1)
	}
	return keystoreV2.NewServerKeyStore(keyDirectory)
}
