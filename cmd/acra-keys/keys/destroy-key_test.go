package keys

import (
	"encoding/base64"
	"errors"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/cossacklabs/acra/cmd/args"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
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

	extractor := args.NewServiceExtractor(flagSet, map[string]interface{}{})

	t.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	t.Run("read storage-public key", func(t *testing.T) {
		destroyCMD := &DestroyKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			contextID:      clientID,
			destroyKeyKind: keystore.KeyStorageKeypair,
			extractor:      extractor,
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
			extractor:      extractor,
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
			extractor:      extractor,
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
			extractor:      extractor,
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
			extractor:      extractor,
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

	extractor := args.NewServiceExtractor(flagSet, map[string]interface{}{})

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
			extractor:      extractor,
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
			extractor:      extractor,
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
			extractor:      extractor,
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
			extractor:      extractor,
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
			extractor:      extractor,
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

func TestDestroyRotatedCMD_FS_V1(t *testing.T) {
	timesToRotated := 3
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

	extractor := args.NewServiceExtractor(flagSet, map[string]interface{}{})

	tcasesWithSymmetricKeys := []struct {
		destroyKeyKind  string
		generateKeyFunc func(store *filesystem.KeyStore) error
	}{
		{
			destroyKeyKind: keystore.KeySearch,
			generateKeyFunc: func(store *filesystem.KeyStore) error {
				return store.GenerateHmacKey(clientID)
			},
		},
		{
			destroyKeyKind: keystore.KeySymmetric,
			generateKeyFunc: func(store *filesystem.KeyStore) error {
				return store.GenerateClientIDSymmetricKey(clientID)
			},
		},
		{
			destroyKeyKind: keystore.KeyPoisonSymmetric,
			generateKeyFunc: func(store *filesystem.KeyStore) error {
				return store.GeneratePoisonSymmetricKey()
			},
		},
	}

	for _, tcase := range tcasesWithSymmetricKeys {
		dirName := t.TempDir()
		if err := os.Chmod(dirName, 0700); err != nil {
			t.Fatal(err)
		}

		destroyCMD := &DestroyKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			index:          2,
			contextID:      clientID,
			destroyKeyKind: tcase.destroyKeyKind,
			FlagSet:        flagSet,
			extractor:      extractor,
		}

		store, err := openKeyStoreV1(destroyCMD)
		if err != nil {
			t.Fatal(err)
		}

		if err = tcase.generateKeyFunc(store); err != nil {
			t.Fatal(err)
		}

		// rotate keys several times
		for i := 0; i < timesToRotated; i++ {
			if err = tcase.generateKeyFunc(store); err != nil {
				t.Fatal(err)
			}
		}

		rotatedKeys, err := store.ListRotatedKeys()
		if err != nil {
			t.Fatal(err)
		}

		if len(rotatedKeys) != timesToRotated {
			t.Fatalf("expected %d rotated keys, but got %d", timesToRotated, len(rotatedKeys))
		}

		// destroy rotated key
		err = DestroyKey(destroyCMD, store)
		if err != nil {
			t.Fatal(err)
		}

		rotatedKeysAfterDestruction, err := store.ListRotatedKeys()
		if err != nil {
			t.Fatal(err)
		}

		if len(rotatedKeysAfterDestruction) != timesToRotated-1 {
			t.Fatalf("expected %d rotated keys, but got %d", timesToRotated-1, len(rotatedKeysAfterDestruction))
		}

		for i := 0; i < len(rotatedKeysAfterDestruction); i++ {
			if rotatedKeysAfterDestruction[i].CreationTime.Format(time.RFC3339) != rotatedKeys[i+1].CreationTime.Format(time.RFC3339) {
				t.Fatalf("expected keys to be equal but got %s != %s", rotatedKeysAfterDestruction[i].CreationTime.Format(time.RFC3339), rotatedKeys[i+1].CreationTime.Format(time.RFC3339))
			}
		}
	}

	tcasesWithKeyPairs := []struct {
		destroyKeyKind  string
		generateKeyFunc func(store *filesystem.KeyStore) error
	}{
		{
			destroyKeyKind: keystore.KeyStorageKeypair,
			generateKeyFunc: func(store *filesystem.KeyStore) error {
				return store.GenerateDataEncryptionKeys(clientID)
			},
		},
		{
			destroyKeyKind: keystore.KeyPoisonKeypair,
			generateKeyFunc: func(store *filesystem.KeyStore) error {
				return store.GeneratePoisonKeyPair()
			},
		},
	}

	for _, tcase := range tcasesWithKeyPairs {
		dirName := t.TempDir()
		if err := os.Chmod(dirName, 0700); err != nil {
			t.Fatal(err)
		}

		destroyCMD := &DestroyKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			// destroy first rotated key
			index:          2,
			contextID:      clientID,
			destroyKeyKind: tcase.destroyKeyKind,
			FlagSet:        flagSet,
			extractor:      extractor,
		}

		store, err := openKeyStoreV1(destroyCMD)
		if err != nil {
			t.Fatal(err)
		}

		if err = tcase.generateKeyFunc(store); err != nil {
			t.Fatal(err)
		}

		// rotate keys several times
		for i := 0; i < timesToRotated; i++ {
			if err = tcase.generateKeyFunc(store); err != nil {
				t.Fatal(err)
			}
		}

		rotatedKeys, err := store.ListRotatedKeys()
		if err != nil {
			t.Fatal(err)
		}

		// expected timesToRotated of private keys and timesToRotated * 2 public keys
		if len(rotatedKeys) != timesToRotated*2 {
			t.Fatalf("expected %d rotated keys, but got %d", timesToRotated, len(rotatedKeys))
		}

		// destroy first rotated key
		err = DestroyKey(destroyCMD, store)
		if err != nil {
			t.Fatal(err)
		}

		rotatedKeysAfterDestruction, err := store.ListRotatedKeys()
		if err != nil {
			t.Fatal(err)
		}

		// without one public and one private key
		if len(rotatedKeysAfterDestruction) != (timesToRotated-1)*2 {
			t.Fatalf("expected %d rotated keys, but got %d", timesToRotated-1, len(rotatedKeysAfterDestruction))
		}

		for i := 0; i < len(rotatedKeysAfterDestruction); i++ {
			if rotatedKeysAfterDestruction[i].CreationTime.Format(time.RFC3339) != rotatedKeys[i+1].CreationTime.Format(time.RFC3339) {
				t.Fatalf("expected keys to be equal but got %s != %s", rotatedKeysAfterDestruction[i].CreationTime.Format(time.RFC3339), rotatedKeys[i+1].CreationTime.Format(time.RFC3339))
			}
		}
	}
}

func TestDestroyRotatedCMD_FS_V2(t *testing.T) {
	timesToRotated := 3
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

	extractor := args.NewServiceExtractor(flagSet, map[string]interface{}{})

	tcases := []struct {
		destroyKeyKind  string
		generateKeyFunc func(store *keystoreV2.ServerKeyStore) error
	}{
		{
			destroyKeyKind: keystore.KeySearch,
			generateKeyFunc: func(store *keystoreV2.ServerKeyStore) error {
				return store.GenerateHmacKey(clientID)
			},
		},

		{
			destroyKeyKind: keystore.KeyStorageKeypair,
			generateKeyFunc: func(store *keystoreV2.ServerKeyStore) error {
				return store.GenerateDataEncryptionKeys(clientID)
			},
		},

		{
			destroyKeyKind: keystore.KeySymmetric,
			generateKeyFunc: func(store *keystoreV2.ServerKeyStore) error {
				return store.GenerateClientIDSymmetricKey(clientID)
			},
		},
		{
			destroyKeyKind: keystore.KeyPoisonSymmetric,
			generateKeyFunc: func(store *keystoreV2.ServerKeyStore) error {
				return store.GeneratePoisonSymmetricKey()
			},
		},
		{
			destroyKeyKind: keystore.KeyPoisonKeypair,
			generateKeyFunc: func(store *keystoreV2.ServerKeyStore) error {
				return store.GeneratePoisonKeyPair()
			},
		},
	}

	t.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	t.Run("test rotated destruction working properly", func(t *testing.T) {
		for _, tcase := range tcases {
			dirName := t.TempDir()
			if err := os.Chmod(dirName, 0700); err != nil {
				t.Fatal(err)
			}

			destroyCMD := &DestroyKeySubcommand{
				CommonKeyStoreParameters: CommonKeyStoreParameters{
					keyDir: dirName,
				},
				index:          2,
				contextID:      clientID,
				destroyKeyKind: tcase.destroyKeyKind,
				FlagSet:        flagSet,
				extractor:      extractor,
			}

			store, err := openKeyStoreV2(destroyCMD)
			if err != nil {
				t.Fatal(err)
			}

			if err = tcase.generateKeyFunc(store); err != nil {
				t.Fatal(err)
			}

			// rotate keys several times
			for i := 0; i < timesToRotated; i++ {
				if err = tcase.generateKeyFunc(store); err != nil {
					t.Fatal(err)
				}
			}

			rotatedKeys, err := store.ListRotatedKeys()
			if err != nil {
				t.Fatal(err)
			}

			if len(rotatedKeys) != timesToRotated {
				t.Fatalf("expected %d rotated keys, but got %d", timesToRotated, len(rotatedKeys))
			}

			// destroy rotated key
			err = DestroyKey(destroyCMD, store)
			if err != nil {
				t.Fatal(err)
			}

			rotatedKeysAfterDestruction, err := store.ListRotatedKeys()
			if err != nil {
				t.Fatal(err)
			}

			if len(rotatedKeysAfterDestruction) != timesToRotated-1 {
				t.Fatalf("expected %d rotated keys, but got %d", timesToRotated-1, len(rotatedKeysAfterDestruction))
			}

			for i := 0; i < len(rotatedKeysAfterDestruction); i++ {
				if rotatedKeysAfterDestruction[i].CreationTime.Format(time.RFC3339) != rotatedKeys[i+1].CreationTime.Format(time.RFC3339) {
					t.Fatalf("expected keys to be equal but got %s != %s", rotatedKeysAfterDestruction[i].CreationTime.Format(time.RFC3339), rotatedKeys[i+1].CreationTime.Format(time.RFC3339))
				}
			}
		}
	})

	t.Run("test shifting ids after rotated keys destruction", func(t *testing.T) {
		for _, tcase := range tcases {
			dirName := t.TempDir()
			if err := os.Chmod(dirName, 0700); err != nil {
				t.Fatal(err)
			}

			destroyCMD := &DestroyKeySubcommand{
				CommonKeyStoreParameters: CommonKeyStoreParameters{
					keyDir: dirName,
				},
				contextID:      clientID,
				destroyKeyKind: tcase.destroyKeyKind,
				FlagSet:        flagSet,
				extractor:      extractor,
			}

			store, err := openKeyStoreV2(destroyCMD)
			if err != nil {
				t.Fatal(err)
			}

			if err = tcase.generateKeyFunc(store); err != nil {
				t.Fatal(err)
			}

			// rotate keys several times
			for i := 0; i < timesToRotated; i++ {
				if err = tcase.generateKeyFunc(store); err != nil {
					t.Fatal(err)
				}
			}

			rotatedKeys, err := store.ListRotatedKeys()
			if err != nil {
				t.Fatal(err)
			}

			if len(rotatedKeys) != timesToRotated {
				t.Fatalf("expected %d rotated keys, but got %d", timesToRotated, len(rotatedKeys))
			}

			// test invalid index
			destroyCMD.index = timesToRotated * 2
			if err := DestroyKey(destroyCMD, store); err == nil {
				t.Fatal("expected error on destroying invalid index, but got nil")
			}

			// valid index - first rotated key
			destroyCMD.index = 2

			for i := 1; i < timesToRotated; i++ {
				// test destroy valid index
				// check no error on destroying the same index again, indexes should be shifted
				if err := DestroyKey(destroyCMD, store); err != nil {
					t.Fatal("expected no error on destroying valid index, but got ", err)
				}

				rotatedKeys, err = store.ListRotatedKeys()
				if err != nil {
					t.Fatal(err)
				}

				if len(rotatedKeys) != timesToRotated-i {
					t.Fatalf("expected %d rotated keys, but got %d", timesToRotated-i, len(rotatedKeys))
				}

				// check rotatedKeys indexes shifted properly
				expectedKeyIdx := 2
				for _, rotatedKey := range rotatedKeys {
					if rotatedKey.Index != expectedKeyIdx {
						t.Fatalf("expected rotated key index %d but got %d", expectedKeyIdx, rotatedKey.Index)
					}
					expectedKeyIdx++
				}
			}
		}
	})
}
