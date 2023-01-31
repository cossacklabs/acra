package keys

import (
	"encoding/base64"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/keystore/keyloader/env_loader"
)

func TestExport_Import_CMD_FS_V1(t *testing.T) {
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

	keyStoreEncryptor, err := keyloader.CreateKeyEncryptor(flagSet, "")
	if err != nil {
		t.Fatal("Can't init keystore KeyEncryptor")
	}

	var (
		keysFile = "access-keys.txt"
		dataFile = "keys.dat"
	)

	t.Run("export/import storage private key", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Expected no panics in command")
			}
		}()

		exportDirName := t.TempDir()
		if err := os.Chmod(exportDirName, 0700); err != nil {
			t.Fatal(err)
		}

		importDirName := t.TempDir()
		if err := os.Chmod(importDirName, 0700); err != nil {
			t.Fatal(err)
		}

		exportBackuper, err := filesystem.NewKeyBackuper(exportDirName, exportDirName, &filesystem.DummyStorage{}, keyStoreEncryptor)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}

		exportCMD := &ExportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: exportDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			exportIDs:     []string{"testclientid_storage"},
			FlagSet:       flagSet,
			exportPrivate: true,
			exporter:      exportBackuper,
		}

		store, err := openKeyStoreV1(exportCMD)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateDataEncryptionKeys(clientID)
		if err != nil {
			t.Fatal(err)
		}

		ExportKeysCommand(exportCMD)

		importBackuper, err := filesystem.NewKeyBackuper(importDirName, importDirName, &filesystem.DummyStorage{}, keyStoreEncryptor)
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

		_, err = os.ReadFile(filepath.Join(importDirName, "testclientid_storage"))
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("export/import hmac symmetric key", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Expected no panics in command")
			}
		}()

		exportDirName := t.TempDir()
		if err := os.Chmod(exportDirName, 0700); err != nil {
			t.Fatal(err)
		}

		importDirName := t.TempDir()
		if err := os.Chmod(importDirName, 0700); err != nil {
			t.Fatal(err)
		}

		exportBackuper, err := filesystem.NewKeyBackuper(exportDirName, exportDirName, &filesystem.DummyStorage{}, keyStoreEncryptor)
		if err != nil {
			t.Fatal("Can't initialize backuper")
		}

		exportCMD := &ExportKeysSubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: exportDirName,
			},
			CommonExportImportParameters: CommonExportImportParameters{
				exportKeysFile: filepath.Join(exportDirName, keysFile),
				exportDataFile: filepath.Join(exportDirName, dataFile),
			},
			exportIDs:     []string{"testclientid_hmac"},
			FlagSet:       flagSet,
			exportPrivate: true,
			exporter:      exportBackuper,
		}

		store, err := openKeyStoreV1(exportCMD)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateHmacKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		ExportKeysCommand(exportCMD)

		importBackuper, err := filesystem.NewKeyBackuper(importDirName, importDirName, &filesystem.DummyStorage{}, keyStoreEncryptor)
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

		_, err = os.ReadFile(filepath.Join(importDirName, "testclientid_hmac"))
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("export/import all keys (storage/symmteric)", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Expected no panics in command")
			}
		}()

		exportDirName := t.TempDir()
		if err := os.Chmod(exportDirName, 0700); err != nil {
			t.Fatal(err)
		}

		importDirName := t.TempDir()
		if err := os.Chmod(importDirName, 0700); err != nil {
			t.Fatal(err)
		}

		exportBackuper, err := filesystem.NewKeyBackuper(exportDirName, exportDirName, &filesystem.DummyStorage{}, keyStoreEncryptor)
		if err != nil {
			t.Fatal("Can't initialize backuper")
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
			exporter:  exportBackuper,
		}

		store, err := openKeyStoreV1(exportCMD)
		if err != nil {
			t.Fatal(err)
		}

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

		importBackuper, err := filesystem.NewKeyBackuper(importDirName, importDirName, &filesystem.DummyStorage{}, keyStoreEncryptor)
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

		for _, key := range []string{"testclientid_storage", "testclientid_storage_sym", "testclientid_hmac", "testclientid_storage.pub"} {
			_, err = os.ReadFile(filepath.Join(importDirName, key))
			if err != nil {
				t.Fatal(err)
			}
		}
	})
}
