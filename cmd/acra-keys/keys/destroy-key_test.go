package keys

import (
	"encoding/base64"
	"errors"
	"flag"
	"os"
	"testing"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/keystore/keyloader/env_loader"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
)

func TestDestroyCMD_FS_V2(t *testing.T) {
	dirName := t.TempDir()
	if err := os.Chmod(dirName, 0700); err != nil {
		t.Fatal(err)
	}

	clientID := []byte("testclientid")

	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyEnvMasterKey, env_loader.NewEnvKeyEncryptorFabric(keystore.AcraMasterKeyVarName))
	masterKey, err := keystoreV2.NewSerializedMasterKeys()
	if err != nil {
		t.Fatal(err)
	}
	flagSet := flag.NewFlagSet(CmdMigrateKeys, flag.ContinueOnError)
	keyloader.RegisterCLIParametersWithFlagSet(flagSet, "", "")

	err = flagSet.Set("keystore_encryption_type", keyloader.KeystoreStrategyEnvMasterKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	t.Run("read storage-public key", func(t *testing.T) {
		destroyCMD := &DestroyKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			contextID:      clientID,
			destroyKeyKind: keystore.KeyStorageKeypair,
			FlagSet:        flagSet,
		}

		store, err := openKeyStoreV2(destroyCMD)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateDataEncryptionKeys(clientID)
		if err != nil {
			t.Fatal(err)
		}

		_, err = store.GetClientIDEncryptionPublicKey(clientID)
		if err != nil {
			t.Fatal("expected nil error after reading created key")
		}

		err = DestroyKey(destroyCMD, store)
		if err != nil {
			t.Fatal(err)
		}

		_, err = store.GetClientIDEncryptionPublicKey(clientID)
		if err != api.ErrKeyDestroyed {
			t.Fatal(errors.New("expected error destroyed key"))
		}
	})

	t.Run("destroy storage symmetric key", func(t *testing.T) {
		destroyCMD := &DestroyKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			contextID:      clientID,
			destroyKeyKind: keystore.KeySymmetric,
			FlagSet:        flagSet,
		}

		store, err := openKeyStoreV2(destroyCMD)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateClientIDSymmetricKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		_, err = store.GetClientIDSymmetricKey(clientID)
		if err != nil {
			t.Fatal("expected nil error after reading created key")
		}

		err = DestroyKey(destroyCMD, store)
		if err != nil {
			t.Fatal(err)
		}

		_, err = store.GetClientIDSymmetricKey(clientID)
		if err != api.ErrKeyDestroyed {
			t.Fatal(errors.New("expected error destroyed key"))
		}
	})

	t.Run("destroy poison key pair", func(t *testing.T) {
		destroyCMD := &DestroyKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			contextID:      clientID,
			destroyKeyKind: keystore.KeyPoisonKeypair,
			FlagSet:        flagSet,
		}

		store, err := openKeyStoreV2(destroyCMD)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GeneratePoisonKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		err = DestroyKey(destroyCMD, store)
		if err != nil {
			t.Fatal(err)
		}

		_, err = store.GetPoisonKeyPair()
		if err != api.ErrKeyDestroyed {
			t.Fatal(errors.New("expected error destroyed key"))
		}
	})

	t.Run("destroy poison symmetric key", func(t *testing.T) {
		destroyCMD := &DestroyKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			contextID:      clientID,
			destroyKeyKind: keystore.KeyPoisonSymmetric,
			FlagSet:        flagSet,
		}

		store, err := openKeyStoreV2(destroyCMD)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GeneratePoisonSymmetricKey()
		if err != nil {
			t.Fatal(err)
		}

		_, err = store.GetPoisonSymmetricKey()
		if err != nil {
			t.Fatal("expected nil error after reading created key")
		}

		err = DestroyKey(destroyCMD, store)
		if err != nil {
			t.Fatal(err)
		}

		_, err = store.GetPoisonSymmetricKey()
		if err != api.ErrKeyDestroyed {
			t.Fatal(errors.New("expected error destroyed key"))
		}
	})

	t.Run("destroy searchable key", func(t *testing.T) {
		destroyCMD := &DestroyKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			contextID:      clientID,
			destroyKeyKind: keystore.KeySearch,
			FlagSet:        flagSet,
		}

		store, err := openKeyStoreV2(destroyCMD)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateHmacKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		_, err = store.GetHMACSecretKey(clientID)
		if err != nil {
			t.Fatal("expected nil error after reading created key")
		}

		err = DestroyKey(destroyCMD, store)
		if err != nil {
			t.Fatal(err)
		}

		_, err = store.GetHMACSecretKey(clientID)
		if err != api.ErrKeyDestroyed {
			t.Fatal(errors.New("expected error destroyed key"))
		}
	})
}

func TestDestroyCMD_FS_V1(t *testing.T) {
	clientID := []byte("testclientid")
	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyEnvMasterKey, env_loader.NewEnvKeyEncryptorFabric(keystore.AcraMasterKeyVarName))

	masterKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	flagSet := flag.NewFlagSet(CmdMigrateKeys, flag.ContinueOnError)
	keyloader.RegisterCLIParametersWithFlagSet(flagSet, "", "")

	err = flagSet.Set("keystore_encryption_type", keyloader.KeystoreStrategyEnvMasterKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	dirName := t.TempDir()
	if err := os.Chmod(dirName, 0700); err != nil {
		t.Fatal(err)
	}

	t.Run("destroy storage key pair", func(t *testing.T) {
		destroyCMD := &DestroyKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			contextID:      clientID,
			destroyKeyKind: keystore.KeyStorageKeypair,
			FlagSet:        flagSet,
		}

		store, err := openKeyStoreV1(destroyCMD)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateDataEncryptionKeys(clientID)
		if err != nil {
			t.Fatal(err)
		}

		err = DestroyKey(destroyCMD, store)
		if err != nil {
			t.Fatal(err)
		}

		_, err = store.GetClientIDEncryptionPublicKey(clientID)
		if err == nil || !os.IsNotExist(err) {
			t.Fatal(errors.New("expected not exit error after key destruction"))
		}
	})

	t.Run("destroy storage symmetric key", func(t *testing.T) {
		destroyCMD := &DestroyKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			contextID:      clientID,
			destroyKeyKind: keystore.KeySymmetric,
			FlagSet:        flagSet,
		}

		store, err := openKeyStoreV1(destroyCMD)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateClientIDSymmetricKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		err = DestroyKey(destroyCMD, store)
		if err != nil {
			t.Fatal(err)
		}

		_, err = store.GetClientIDSymmetricKey(clientID)
		if err == nil || !os.IsNotExist(err) {
			t.Fatal(errors.New("expected not exit error after key destruction"))
		}
	})

	t.Run("destroy poison key pair", func(t *testing.T) {
		destroyCMD := &DestroyKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			contextID:      clientID,
			destroyKeyKind: keystore.KeyPoisonKeypair,
			FlagSet:        flagSet,
		}

		store, err := openKeyStoreV1(destroyCMD)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GeneratePoisonKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		err = DestroyKey(destroyCMD, store)
		if err != nil {
			t.Fatal(err)
		}

		_, err = store.GetPoisonKeyPair()
		if err == nil {
			t.Fatal(errors.New("expected not exit error after key destruction"))
		}
	})

	t.Run("destroy poison symmetric key", func(t *testing.T) {
		destroyCMD := &DestroyKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			contextID:      clientID,
			destroyKeyKind: keystore.KeyPoisonSymmetric,
			FlagSet:        flagSet,
		}

		store, err := openKeyStoreV1(destroyCMD)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GeneratePoisonSymmetricKey()
		if err != nil {
			t.Fatal(err)
		}

		err = DestroyKey(destroyCMD, store)
		if err != nil {
			t.Fatal(err)
		}

		_, err = store.GetPoisonSymmetricKey()
		if err == nil {
			t.Fatal(errors.New("expected not exit error after key destruction"))
		}
	})

	t.Run("destroy searchable key", func(t *testing.T) {
		destroyCMD := &DestroyKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			contextID:      clientID,
			destroyKeyKind: keystore.KeySearch,
			FlagSet:        flagSet,
		}

		store, err := openKeyStoreV1(destroyCMD)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateHmacKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		err = DestroyKey(destroyCMD, store)
		if err != nil {
			t.Fatal(err)
		}

		_, err = store.GetHMACSecretKey(clientID)
		if err == nil {
			t.Fatal(errors.New("expected not exit error after key destruction"))
		}
	})
}
