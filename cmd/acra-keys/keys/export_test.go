package keys

import (
	"encoding/base64"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/keystore/keyloader/env_loader"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
)

func TestExport_Import_CMD_FS_V1(t *testing.T) {
	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyEnvMasterKey, env_loader.NewEnvKeyEncryptorFabric(keystore.AcraMasterKeyVarName))

	masterKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	flagSet := flag.NewFlagSet(CmdExportKeys, flag.ContinueOnError)
	keyloader.RegisterCLIParametersWithFlagSet(flagSet, "", "")

	err = flagSet.Set("keystore_encryption_type", keyloader.KeystoreStrategyEnvMasterKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	keyStoreEncryptor, err := keyloader.CreateKeyEncryptor(flagSet, "")
	if err != nil {
		t.Fatal("Can't init keystore KeyEncryptor")
	}

	var (
		keysFile = "access-keys.txt"
		dataFile = "keys.dat"
		clientID = []byte("testclientid")
	)

	t.Run("export/import poison private key", func(t *testing.T) {
		exportDirName := t.TempDir()
		if err := os.Chmod(exportDirName, 0700); err != nil {
			t.Fatal(err)
		}

		importDirName := t.TempDir()
		if err := os.Chmod(importDirName, 0700); err != nil {
			t.Fatal(err)
		}

		var exportCMD = &ExportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: exportDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			exportIDs: []keystore.ExportID{{
				KeyKind:   keystore.KeyPoisonPrivate,
				ContextID: clientID,
			}},
			FlagSet:       flagSet,
			exportPrivate: true,
		}

		store, err := openKeyStoreV1(exportCMD)
		if err != nil {
			t.Fatal(err)
		}

		exportBackuper, err := filesystem.NewKeyBackuper(exportDirName, exportDirName, &filesystem.DummyStorage{}, keyStoreEncryptor, store)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}

		exportCMD.exporter = exportBackuper

		err = store.GeneratePoisonKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		ExportKeysCommand(exportCMD)

		importBackuper, err := filesystem.NewKeyBackuper(importDirName, importDirName, &filesystem.DummyStorage{}, keyStoreEncryptor, store)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}

		importCMD := &ImportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: importDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			FlagSet:  flagSet,
			importer: importBackuper,
		}

		ImportKeysCommand(importCMD)

		importKeyStore, err := openKeyStoreV1(importCMD)
		if err != nil {
			t.Fatal(err)
		}

		_, err = importKeyStore.GetPoisonPrivateKeys()
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("export/import hmac symmetric key", func(t *testing.T) {
		exportDirName := t.TempDir()
		if err := os.Chmod(exportDirName, 0700); err != nil {
			t.Fatal(err)
		}

		importDirName := t.TempDir()
		if err := os.Chmod(importDirName, 0700); err != nil {
			t.Fatal(err)
		}

		exportCMD := &ExportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: exportDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			exportIDs: []keystore.ExportID{{
				KeyKind:   keystore.KeySearch,
				ContextID: clientID,
			}},
			FlagSet:       flagSet,
			exportPrivate: true,
		}

		store, err := openKeyStoreV1(exportCMD)
		if err != nil {
			t.Fatal(err)
		}

		exportBackuper, err := filesystem.NewKeyBackuper(exportDirName, exportDirName, &filesystem.DummyStorage{}, keyStoreEncryptor, store)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}

		exportCMD.exporter = exportBackuper

		err = store.GenerateHmacKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		ExportKeysCommand(exportCMD)

		importBackuper, err := filesystem.NewKeyBackuper(importDirName, importDirName, &filesystem.DummyStorage{}, keyStoreEncryptor, nil)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}

		importCMD := &ImportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: importDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			FlagSet:  flagSet,
			importer: importBackuper,
		}

		ImportKeysCommand(importCMD)

		importKeyStore, err := openKeyStoreV1(importCMD)
		if err != nil {
			t.Fatal(err)
		}

		_, err = importKeyStore.GetHMACSecretKey(clientID)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("export/import all keys (storage/symmteric)", func(t *testing.T) {
		exportDirName := t.TempDir()
		if err := os.Chmod(exportDirName, 0700); err != nil {
			t.Fatal(err)
		}

		importDirName := t.TempDir()
		if err := os.Chmod(importDirName, 0700); err != nil {
			t.Fatal(err)
		}

		exportCMD := &ExportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: exportDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			FlagSet:   flagSet,
			exportAll: true,
		}

		store, err := openKeyStoreV1(exportCMD)
		if err != nil {
			t.Fatal(err)
		}

		exportBackuper, err := filesystem.NewKeyBackuper(exportDirName, exportDirName, &filesystem.DummyStorage{}, keyStoreEncryptor, store)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}
		exportCMD.exporter = exportBackuper

		err = store.GenerateHmacKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateDataEncryptionKeys(clientID)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateClientIDSymmetricKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		ExportKeysCommand(exportCMD)

		importBackuper, err := filesystem.NewKeyBackuper(importDirName, importDirName, &filesystem.DummyStorage{}, keyStoreEncryptor, nil)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}

		importCMD := &ImportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: importDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			FlagSet:  flagSet,
			importer: importBackuper,
		}

		ImportKeysCommand(importCMD)

		importKeyStore, err := openKeyStoreV1(importCMD)
		if err != nil {
			t.Fatal(err)
		}

		_, err = importKeyStore.GetHMACSecretKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		_, err = importKeyStore.GetClientIDSymmetricKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		_, err = importKeyStore.GetClientIDEncryptionPublicKey(clientID)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("export/import keys by keyID and path (storage/symmetric)", func(t *testing.T) {
		exportDirName := t.TempDir()
		if err := os.Chmod(exportDirName, 0700); err != nil {
			t.Fatal(err)
		}

		importDirName := t.TempDir()
		if err := os.Chmod(importDirName, 0700); err != nil {
			t.Fatal(err)
		}

		exportCMD := &ExportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: exportDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			FlagSet:       flagSet,
			exportPrivate: true,
		}
		err := exportCMD.Parse([]string{
			"client/testclientid/symmetric",
			"testclientid_hmac",
			"testclientid_storage",
		})
		if err != nil {
			t.Fatal(err)
		}

		store, err := openKeyStoreV1(exportCMD)
		if err != nil {
			t.Fatal(err)
		}

		exportBackuper, err := filesystem.NewKeyBackuper(exportDirName, exportDirName, &filesystem.DummyStorage{}, keyStoreEncryptor, store)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}

		exportCMD.exporter = exportBackuper
		err = store.GenerateHmacKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateDataEncryptionKeys(clientID)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateClientIDSymmetricKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		ExportKeysCommand(exportCMD)

		importBackuper, err := filesystem.NewKeyBackuper(importDirName, importDirName, &filesystem.DummyStorage{}, keyStoreEncryptor, nil)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}

		importCMD := &ImportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: importDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			FlagSet:  flagSet,
			importer: importBackuper,
		}

		ImportKeysCommand(importCMD)

		importKeyStore, err := openKeyStoreV1(importCMD)
		if err != nil {
			t.Fatal(err)
		}

		_, err = importKeyStore.GetHMACSecretKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		_, err = importKeyStore.GetClientIDSymmetricKey(clientID)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestExport_Import_CMD_FS_V1_Invalid_Cases(t *testing.T) {
	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyEnvMasterKey, env_loader.NewEnvKeyEncryptorFabric(keystore.AcraMasterKeyVarName))

	masterKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	flagSet := flag.NewFlagSet(CmdExportKeys, flag.ContinueOnError)
	keyloader.RegisterCLIParametersWithFlagSet(flagSet, "", "")

	err = flagSet.Set("keystore_encryption_type", keyloader.KeystoreStrategyEnvMasterKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	keyStoreEncryptor, err := keyloader.CreateKeyEncryptor(flagSet, "")
	if err != nil {
		t.Fatal("Can't init keystore KeyEncryptor")
	}

	var (
		keysFile = "access-keys.txt"
		dataFile = "keys.dat"
		clientID = []byte("testclientid")
	)

	t.Run("export/import invalid storage private key", func(t *testing.T) {
		exportDirName := t.TempDir()
		if err := os.Chmod(exportDirName, 0700); err != nil {
			t.Fatal(err)
		}

		var exportCMD = &ExportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: exportDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			exportIDs: []keystore.ExportID{{
				KeyKind:   keystore.KeyStoragePrivate,
				ContextID: clientID,
			}},
			FlagSet:       flagSet,
			exportPrivate: true,
		}

		store, err := openKeyStoreV1(exportCMD)
		if err != nil {
			t.Fatal(err)
		}

		exportBackuper, err := filesystem.NewKeyBackuper(exportDirName, exportDirName, &filesystem.DummyStorage{}, keyStoreEncryptor, store)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}

		exportCMD.exporter = exportBackuper

		keyPath := filepath.Join(exportDirName, string(clientID)+"_storage")

		// creating invalid key
		if err := os.WriteFile(keyPath, []byte("invalid-key-data"), 0600); err != nil {
			t.Fatal(err)
		}

		_, err = exportCMD.exporter.Export(exportCMD.exportIDs, keystore.ExportPrivateKeys)
		if err == nil {
			t.Fatal("Expected error, on export invalid key")
		}

		// fail to Decryption invalid key
		if err.Error() != "failed to get output size" {
			t.Fatal("Unexpected error received")
		}

		if err := os.Remove(keyPath); err != nil {
			t.Fatal(err)
		}

		// export non-existed key, expect to fail
		_, err = exportCMD.exporter.Export(exportCMD.exportIDs, keystore.ExportPrivateKeys)
		if err == nil {
			t.Fatal("Expected error, on export invalid key")
		}

		// fail to Decryption invalid key
		if !strings.Contains(err.Error(), "no such file or directory") {
			t.Fatal("Unexpected error received - expected no such file error")
		}
	})

	t.Run("export specified - invalid public key V1", func(t *testing.T) {
		exportDirName := t.TempDir()
		if err := os.Chmod(exportDirName, 0700); err != nil {
			t.Fatal(err)
		}

		importDirName := t.TempDir()
		if err := os.Chmod(importDirName, 0700); err != nil {
			t.Fatal(err)
		}

		var exportCMD = &ExportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: exportDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			exportIDs: []keystore.ExportID{{
				KeyKind:   keystore.KeyStoragePublic,
				ContextID: clientID,
			}},
			FlagSet: flagSet,
		}

		store, err := openKeyStoreV1(exportCMD)
		if err != nil {
			t.Fatal(err)
		}

		exportBackuper, err := filesystem.NewKeyBackuper(exportDirName, exportDirName, &filesystem.DummyStorage{}, keyStoreEncryptor, store)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}

		exportCMD.exporter = exportBackuper

		keyPath := filepath.Join(exportDirName, string(clientID)+"_storage.pub")

		// creating invalid key
		if err := os.WriteFile(keyPath, []byte("invalid-key-data"), 0600); err != nil {
			t.Fatal(err)
		}

		_, err = exportCMD.exporter.Export(exportCMD.exportIDs, keystore.ExportAllKeys)
		if err == nil {
			t.Fatal("Expected error, on export invalid key")
		}

		if err.Error() != "failed to get output size" {
			t.Fatal("Unexpected error received")
		}
	})

	t.Run("export all - invalid public key V1", func(t *testing.T) {
		exportDirName := t.TempDir()
		if err := os.Chmod(exportDirName, 0700); err != nil {
			t.Fatal(err)
		}

		importDirName := t.TempDir()
		if err := os.Chmod(importDirName, 0700); err != nil {
			t.Fatal(err)
		}

		var exportCMD = &ExportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: exportDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			FlagSet: flagSet,
		}

		store, err := openKeyStoreV1(exportCMD)
		if err != nil {
			t.Fatal(err)
		}

		exportBackuper, err := filesystem.NewKeyBackuper(exportDirName, exportDirName, &filesystem.DummyStorage{}, keyStoreEncryptor, store)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}

		exportCMD.exporter = exportBackuper

		keyPath := filepath.Join(exportDirName, string(clientID)+"_storage.pub")

		// creating invalid key
		if err := os.WriteFile(keyPath, []byte("invalid-key-data"), 0600); err != nil {
			t.Fatal(err)
		}

		_, err = exportCMD.exporter.Export(exportCMD.exportIDs, keystore.ExportAllKeys)
		if err == nil {
			t.Fatal("Expected error, on export invalid key")
		}

		if err.Error() != "failed to get output size" {
			t.Fatal("Unexpected error received")
		}
	})

	t.Run("export all - with invalid files V1", func(t *testing.T) {
		exportDirName := t.TempDir()
		if err := os.Chmod(exportDirName, 0700); err != nil {
			t.Fatal(err)
		}

		importDirName := t.TempDir()
		if err := os.Chmod(importDirName, 0700); err != nil {
			t.Fatal(err)
		}

		var exportCMD = &ExportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: exportDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			FlagSet: flagSet,
		}

		store, err := openKeyStoreV1(exportCMD)
		if err != nil {
			t.Fatal(err)
		}

		exportBackuper, err := filesystem.NewKeyBackuper(exportDirName, exportDirName, &filesystem.DummyStorage{}, keyStoreEncryptor, store)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}

		exportCMD.exporter = exportBackuper

		keyPath := filepath.Join(exportDirName, string(clientID)+"_some_file")

		// creating invalid key
		if err := os.WriteFile(keyPath, []byte("invalid-key-data"), 0600); err != nil {
			t.Fatal(err)
		}

		_, err = exportCMD.exporter.Export(exportCMD.exportIDs, keystore.ExportAllKeys)
		if err == nil {
			t.Fatal("Expected error, on export invalid key")
		}

		if err.Error() != "failed to get output size" {
			t.Fatal("Unexpected error received")
		}
	})
}

func TestExport_Import_CMD_FS_V2(t *testing.T) {
	dirName := t.TempDir()
	if err := os.Chmod(dirName, 0700); err != nil {
		t.Fatal(err)
	}

	var (
		keysFile = "access-keys.txt"
		dataFile = "keys.dat"
		clientID = []byte("testclientid")
	)

	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyEnvMasterKey, env_loader.NewEnvKeyEncryptorFabric(keystore.AcraMasterKeyVarName))
	masterKey, err := keystoreV2.NewSerializedMasterKeys()
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	flagSet := flag.NewFlagSet(CmdExportKeys, flag.ContinueOnError)
	keyloader.RegisterCLIParametersWithFlagSet(flagSet, "", "")

	err = flagSet.Set("keystore_encryption_type", keyloader.KeystoreStrategyEnvMasterKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("export/import keys by keyID and path (storage/symmetric)", func(t *testing.T) {

		exportDirName := t.TempDir()
		if err := os.Chmod(exportDirName, 0700); err != nil {
			t.Fatal(err)
		}

		importDirName := t.TempDir()
		if err := os.Chmod(importDirName, 0700); err != nil {
			t.Fatal(err)
		}

		exportCMD := &ExportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: exportDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			FlagSet:       flagSet,
			exportPrivate: true,
		}

		store, err := openKeyStoreV2(exportCMD)
		if err != nil {
			t.Fatal(err)
		}

		exportBackuper, err := keystoreV2.NewKeyBackuper(exportDirName, exportDirName, store)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}

		exportCMD.exporter = exportBackuper
		err = store.GenerateHmacKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateDataEncryptionKeys(clientID)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateClientIDSymmetricKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		err = exportCMD.Parse([]string{
			"client/testclientid/symmetric",
			//specify by path
			"client/testclientid/hmac-sym",
		})
		if err != nil {
			t.Fatal(err)
		}

		ExportKeysCommand(exportCMD)

		importCMD := &ImportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: importDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			FlagSet: flagSet,
		}

		importKeyStore, err := openKeyStoreV2(importCMD)
		if err != nil {
			t.Fatal(err)
		}

		importBackuper, err := keystoreV2.NewKeyBackuper(importDirName, importDirName, importKeyStore)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}
		importCMD.importer = importBackuper

		ImportKeysCommand(importCMD)

		_, err = importKeyStore.GetHMACSecretKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		_, err = importKeyStore.GetClientIDSymmetricKey(clientID)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("export/import invalid public key V2", func(t *testing.T) {
		exportDirName := t.TempDir()
		if err := os.Chmod(exportDirName, 0700); err != nil {
			t.Fatal(err)
		}

		importDirName := t.TempDir()
		if err := os.Chmod(importDirName, 0700); err != nil {
			t.Fatal(err)
		}

		var exportCMD = &ExportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: exportDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			exportIDs: []keystore.ExportID{{
				KeyKind:   keystore.KeyStoragePublic,
				ContextID: clientID,
			}},
			FlagSet: flagSet,
		}

		store, err := openKeyStoreV2(exportCMD)
		if err != nil {
			t.Fatal(err)
		}

		exportBackuper, err := keystoreV2.NewKeyBackuper(exportDirName, exportDirName, store)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}

		exportCMD.exporter = exportBackuper

		keyPath := filepath.Join(filepath.Join(exportDirName, "client"), string(clientID))
		if err := os.MkdirAll(keyPath, 0700); err != nil {
			t.Fatal(err)
		}

		keyPath = filepath.Join(keyPath, "storage.keyring")
		// creating invalid key
		if err := os.WriteFile(keyPath, []byte("invalid-key-data"), 0600); err != nil {
			t.Fatal(err)
		}

		// export non-existed key, expect to fail
		_, err = exportCMD.exporter.Export(exportCMD.exportIDs, keystore.ExportPrivateKeys)
		if err == nil {
			t.Fatal("Expected error, on export invalid key")
		}

		if !strings.Contains(err.Error(), "tags don't match") {
			t.Fatal("Unexpected error received - expected no such file error")
		}
	})
}
