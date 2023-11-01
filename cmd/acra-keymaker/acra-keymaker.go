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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/keystore/keyloader/kms"
	"github.com/cossacklabs/acra/keystore/kms/base"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	filesystemBackendV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
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
	dataKeys := flag.Bool("generate_acrawriter_keys", false, "Create keypair for data encryption/decryption")
	outputDir := flag.String("keys_output_dir", keystore.DefaultKeyDirShort, "Folder where will be saved keys")
	outputPublicKey := flag.String("keys_public_output_dir", keystore.DefaultKeyDirShort, "Folder where will be saved public key")
	hmac := flag.Bool("generate_hmac_key", false, "Create key for HMAC calculation")
	logKey := flag.Bool("generate_log_key", false, "Create key for log integrity checks")
	symStorageKey := flag.Bool("generate_symmetric_storage_key", false, "Generate symmetric key for data encryption/decryption with AcraBlock")
	masterKey := flag.String("generate_master_key", "", "Generate new random master key and save to file")
	poisonRecord := flag.Bool("generate_poisonrecord_keys", false, "Generate keypair and symmetric key for poison records")
	keystoreVersion := flag.String("keystore", "", "set keystore format: v1 (current), v2 (new)")
	kmsKeyPolicy := flag.String("kms_key_policy", kms.KeyPolicyCreate, fmt.Sprintf("KMS usage key policy: <%s>", strings.Join(kms.SupportedPolicies, "|")))

	tlsClientCertOld := flag.String("tls_cert", "", "Path to TLS certificate to use as client_id identifier. Deprecated since 0.96.0 use --tls_client_id_cert")
	tlsClientCertNew := flag.String("tls_client_id_cert", "", "Path to TLS certificate to use as client_id identifier.")
	tlsIdentifierExtractorType := flag.String("tls_identifier_extractor_type", network.IdentifierExtractorTypeDistinguishedName, fmt.Sprintf("Decide which field of TLS certificate to use as ClientID (%s). Default is %s.", strings.Join(network.IdentifierExtractorTypesList, "|"), network.IdentifierExtractorTypeDistinguishedName))

	cmd.RegisterRedisKeystoreParameters()
	keyloader.RegisterKeyStoreStrategyParameters()
	logging.SetLogLevel(logging.LogVerbose)

	if err := cmd.ParseFlags(flag.CommandLine, os.Args[1:]); err != nil {
		if err == cmd.ErrDumpRequested {
			cmd.DumpConfig(DefaultConfigPath, ServiceName, true)
			os.Exit(0)
		}

		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}

	serviceConfig, err := cmd.ParseConfig(DefaultConfigPath, ServiceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse config")
		os.Exit(1)
	}

	paramsExtractor := cmd.NewServiceParamsExtractor(flag.CommandLine, serviceConfig)

	if *tlsClientCertOld != "" && *tlsClientCertNew != "" {
		log.Errorln("You cant specify --tls_cert (deprecated since 0.96.0) and --tls_client_id_cert simultaneously")
		os.Exit(1)
	}

	tlsClientCert := *tlsClientCertNew
	if tlsClientCert == "" && *tlsClientCertOld != "" {
		tlsClientCert = *tlsClientCertOld
	}

	if len(*clientID) != 0 && tlsClientCert != "" {
		log.Errorln("You can either specify identifier for keys via specific clientID by --client_id parameter or via TLS certificate by --tls_cert parameter.")
		os.Exit(1)
	}

	if len(*clientID) == 0 && tlsClientCert != "" {
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
		pemCertificateFile, err := os.ReadFile(tlsClientCert)
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

	// all keys required clientID for generation
	if *dataKeys || *hmac || *symStorageKey {
		cmd.ValidateClientID(*clientID)
	}

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

		if keystoreOptions := keyloader.ParseCLIOptions(paramsExtractor); keystoreOptions.KeystoreEncryptorType == keyloader.KeystoreStrategyKMSMasterKey {
			keyManager, err := kms.NewKeyManager(kms.ParseCLIParameters(paramsExtractor))
			if err != nil {
				log.WithError(err).WithField("path", *masterKey).Errorln("Failed to initializer kms KeyManager")
				os.Exit(1)
			}

			switch *kmsKeyPolicy {
			case kms.KeyPolicyCreate:
				newKey, err = newMasterKeyWithKMSCreate(keyManager, newKey)
				if err != nil {
					log.WithField("path", *masterKey).Errorln("Failed to create key with KMS")
					os.Exit(1)
				}

			default:
				log.WithField("supported", kms.SupportedPolicies).WithField("policy", *kmsKeyPolicy).Errorln("Unsupported key policy for `kms_key_policy`")
				os.Exit(1)
			}
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
		if filesystemV2.IsKeyDirectory(*outputDir, paramsExtractor) {
			*keystoreVersion = "v2"
		} else if filesystem.IsKeyDirectory(*outputDir, paramsExtractor) {
			*keystoreVersion = "v1"
		}
	}

	switch *keystoreVersion {
	case "v1":
		store = openKeyStoreV1(*outputDir, *outputPublicKey, paramsExtractor)
	case "v2":
		store = openKeyStoreV2(*outputDir, paramsExtractor)
	case "":
		log.Errorf("Keystore version is required: --keystore={v1|v2}")
		os.Exit(1)
	default:
		log.Errorf("Unknown --keystore version: %v (supported: v1, v2)", *keystoreVersion)
		os.Exit(1)
	}

	if *poisonRecord {
		// Generate poison record symmetric key
		if err = store.GeneratePoisonSymmetricKey(); err != nil {
			panic(err)
		}
		fmt.Println("Generated symmetric key for poison records")
		// Generate poison record keypair
		if err = store.GeneratePoisonKeyPair(); err != nil {
			panic(err)
		}
		fmt.Println("Generated keypair for poison records")
	}

	if *dataKeys {
		err = store.GenerateDataEncryptionKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated storage encryption keypair")
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

	if !(*dataKeys || *hmac || *poisonRecord || *symStorageKey || *logKey) {
		cmd.ValidateClientID(*clientID)

		err = store.GenerateDataEncryptionKeys([]byte(*clientID))
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated storage encryption keypair")
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
		if err = store.GeneratePoisonSymmetricKey(); err != nil {
			panic(err)
		}
		fmt.Println("Generated symmetric key for poison records")
		// Generate poison record keypair
		if err = store.GeneratePoisonKeyPair(); err != nil {
			panic(err)
		}
		fmt.Println("Generated keypair for poison records")
	}
}

func openKeyStoreV1(output, outputPublic string, extractor *cmd.ServiceParamsExtractor) keystore.KeyMaking {
	var keyStoreEncryptor keystore.KeyEncryptor

	keyStoreEncryptor, err := keyloader.CreateKeyEncryptor(extractor, "")
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore KeyEncryptor")
		os.Exit(1)
	}

	keyStoreBuilder := filesystem.NewCustomFilesystemKeyStore()
	if outputPublic != output {
		keyStoreBuilder.KeyDirectories(output, outputPublic)
	} else {
		keyStoreBuilder.KeyDirectory(output)
	}
	keyStoreBuilder.Encryptor(keyStoreEncryptor)

	if redis := cmd.ParseRedisCLIParameters(extractor); redis.KeysConfigured() {
		// if redisTLS = nil then will not be used TLS for Redis
		var redisTLS *tls.Config
		var err error
		if redis.TLSEnable {
			redisTLS, err = network.NewTLSConfigByName(extractor, "redis", redis.HostPort, network.ClientNameConstructorFunc())
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
					Errorln("Can't initialize TLS config for Redis client")
				os.Exit(1)
			}
		}
		keyStorage, err := filesystem.NewRedisStorage(redis.HostPort, redis.Password, redis.DBKeys, redisTLS)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
				Errorln("Can't initialize Redis client")
			os.Exit(1)
		}
		keyStoreBuilder.Storage(keyStorage)
	}
	keyStore, err := keyStoreBuilder.Build()
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore")
		os.Exit(1)
	}

	if keyLoaderParams := keyloader.ParseCLIOptions(extractor); keyLoaderParams.KeystoreEncryptorType == keyloader.KeystoreStrategyKMSPerClient {
		keyManager, _ := kms.NewKeyManager(kms.ParseCLIParameters(extractor))
		return base.NewKeyMakingWrapper(keyStore, keyManager, kms.NewKMSPerClientKeyMapper())
	}
	return keyStore
}

func openKeyStoreV2(keyDirPath string, extractor *cmd.ServiceParamsExtractor) keystore.KeyMaking {
	keyStoreSuite, err := keyloader.CreateKeyEncryptorSuite(extractor, "")
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore keyStoreSuite")
		os.Exit(1)
	}
	var backend filesystemBackendV2.Backend
	if redis := cmd.ParseRedisCLIParameters(extractor); redis.KeysConfigured() {
		redisOptions, err := redis.KeysOptions(extractor)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize Redis options")
			os.Exit(1)
		}
		config := &filesystemBackendV2.RedisConfig{
			RootDir: keyDirPath,
			Options: redisOptions,
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
	keyDirectory, err := filesystemV2.CustomKeyStore(backend, keyStoreSuite)
	if err != nil {
		log.WithError(err).Error("Failed to initialize key directory")
		os.Exit(1)
	}
	return keystoreV2.NewServerKeyStore(keyDirectory)
}

func newMasterKeyWithKMSCreate(keyManager base.KeyManager, key []byte) ([]byte, error) {
	ctx, _ := context.WithTimeout(context.Background(), network.DefaultNetworkTimeout)

	ok, err := keyManager.IsKeyExist(ctx, kms.AcraMasterKeyKEKID)
	if err != nil {
		log.WithError(err).WithField("key", kms.AcraMasterKeyKEKID).Errorln("Failed to check if key is exist in KMS")
		return nil, err
	}
	if ok {
		log.WithField("key", kms.AcraMasterKeyKEKID).Errorln("Key already exist in KMS")
		return nil, err
	}

	keyMetaData, err := keyManager.CreateKey(ctx, base.CreateKeyMetadata{
		KeyName: kms.AcraMasterKeyKEKID,
	})
	if err != nil {
		log.WithError(err).WithField("key", kms.AcraMasterKeyKEKID).Errorln("Failed to create KMS key")
		return nil, err
	}

	log.WithField("keyID", keyMetaData.KeyID).Infof("New KMS key created")
	key, err = keyManager.Encrypt(ctx, []byte(kms.AcraMasterKeyKEKID), key, nil)
	if err != nil {
		log.WithError(err).WithField("key", kms.AcraMasterKeyKEKID).Errorln("Failed to encrypt with KMS key")
		return nil, err
	}

	return key, nil
}
