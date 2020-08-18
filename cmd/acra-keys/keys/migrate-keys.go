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
	"flag"
	"fmt"
	"os"

	"github.com/cossacklabs/acra/cmd"
	keystoreV1 "github.com/cossacklabs/acra/keystore"
	filesystemV1 "github.com/cossacklabs/acra/keystore/filesystem"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	keystoreAPIV2 "github.com/cossacklabs/acra/keystore/v2/keystore/api"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	log "github.com/sirupsen/logrus"
)

// MigrateKeysParams ara parameters of "acra-keys migrate" subcommand.
type MigrateKeysParams interface {
	SrcKeyStoreVersion() string
	SrcKeyStoreParams() KeyStoreParameters
	DstKeyStoreVersion() string
	DstKeyStoreParams() KeyStoreParameters
	DryRun() bool
	ForceWrite() bool
}

// MigrateKeysSubcommand is the "acra-keys migrate" subcommand.
type MigrateKeysSubcommand struct {
	flagSet    *flag.FlagSet
	src, dst   CommonKeyStoreParameters
	srcVersion string
	dstVersion string
	dryRun     bool
	force      bool
}

// Environment variables from which master keys are read.
const (
	SrcMasterKeyVarName = "SRC_" + keystoreV1.AcraMasterKeyVarName
	DstMasterKeyVarName = "DST_" + keystoreV1.AcraMasterKeyVarName
)

// Command-line errors for "acra-keys migrate":
var (
	ErrMissingFormat = errors.New("keystore format not specified")
	ErrMissingKeyDir = errors.New("keys directory not specified")
)

// SrcKeyStoreVersion returns source key store version.
func (m *MigrateKeysSubcommand) SrcKeyStoreVersion() string {
	return m.srcVersion
}

// SrcKeyStoreParams returns parameters of the source key store.
func (m *MigrateKeysSubcommand) SrcKeyStoreParams() KeyStoreParameters {
	return &m.src
}

// DstKeyStoreVersion returns destination key store version.
func (m *MigrateKeysSubcommand) DstKeyStoreVersion() string {
	return m.dstVersion
}

// DstKeyStoreParams returns parameters of the destination key store.
func (m *MigrateKeysSubcommand) DstKeyStoreParams() KeyStoreParameters {
	return &m.dst
}

// DryRun returns true if only a dry run requested, without actual migration.
func (m *MigrateKeysSubcommand) DryRun() bool {
	return m.dryRun
}

// ForceWrite returns true if migration is allowed to overwrite existing destination key store.
func (m *MigrateKeysSubcommand) ForceWrite() bool {
	return m.force
}

// Name returns the same of this subcommand.
func (m *MigrateKeysSubcommand) Name() string {
	return CmdMigrateKeys
}

// GetFlagSet returns flag set of this subcommand.
func (m *MigrateKeysSubcommand) GetFlagSet() *flag.FlagSet {
	return m.flagSet
}

// RegisterFlags registers command-line flags of "acra-keys migrate".
func (m *MigrateKeysSubcommand) RegisterFlags() {
	m.flagSet = flag.NewFlagSet(CmdMigrateKeys, flag.ContinueOnError)
	m.src.RegisterPrefixed(m.flagSet, "", "src_", "(old keystore, source)")
	m.dst.RegisterPrefixed(m.flagSet, "", "dst_", "(new keystore, destination)")
	m.flagSet.StringVar(&m.srcVersion, "src_keystore", "", "keystore format to use: v1 (current), v2 (new)")
	m.flagSet.StringVar(&m.dstVersion, "dst_keystore", "", "keystore format to use: v1 (current), v2 (new)")
	m.flagSet.BoolVar(&m.dryRun, "dry_run", false, "try migration without writing to the output keystore")
	m.flagSet.BoolVar(&m.force, "force", false, "write to output keystore even if it exists")
	m.flagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": migrate keystore to a different format\n", CmdMigrateKeys)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...] \\\n"+
			"\t\t--src_keystore <src-version> --src_keys_dir <.acrakeys-src> \\\n"+
			"\t\t--dst_keystore <dst-version> --dst_keys_dir <.acrakeys-dst>\n",
			os.Args[0], CmdMigrateKeys)
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(m.flagSet)
	}
}

// Parse command-line parameters of the subcommand.
func (m *MigrateKeysSubcommand) Parse(arguments []string) error {
	err := cmd.ParseFlagsWithConfig(m.flagSet, arguments, DefaultConfigPath, ServiceName)
	if err != nil {
		return err
	}

	if m.srcVersion == "" {
		log.Warning("Missing required argument: --src_keystore={v1|v2}")
	}
	if m.dstVersion == "" {
		log.Warning("Missing required argument: --dst_keystore={v1|v2}")
	}
	if m.srcVersion == "" || m.dstVersion == "" {
		return ErrMissingFormat
	}

	if m.src.keyDir == "" {
		log.Warning("Missing required argument: --src_keys_dir=<path>")
	}
	if m.dst.keyDir == "" {
		log.Warning("Missing required argument: --dst_keys_dir=<path>")
	}
	if m.src.keyDir == "" || m.dst.keyDir == "" {
		return ErrMissingKeyDir
	}

	if m.src.keyDirPublic == "" {
		m.src.keyDirPublic = m.src.keyDir
	}
	if m.dst.keyDirPublic == "" {
		m.dst.keyDirPublic = m.dst.keyDir
	}

	return nil
}

// Execute this subcommand.
func (m *MigrateKeysSubcommand) Execute() {
	if m.SrcKeyStoreVersion() == "v1" && m.DstKeyStoreVersion() == "v2" {
		keyStoreV1, err := m.openKeyStoreV1(SrcMasterKeyVarName, m.SrcKeyStoreParams())
		if err != nil {
			log.WithError(err).Fatal("Failed to open keystore v1 (src)")
		}
		keyStoreV2, err := m.openKeyStoreV2(DstMasterKeyVarName, m.DstKeyStoreParams())
		if err != nil {
			log.WithError(err).Fatal("Failed to open keystore v2 (dst)")
		}
		err = MigrateV1toV2(keyStoreV1, keyStoreV2)
		if err != nil {
			log.WithError(err).Fatal("Migration failed")
		}
		log.Infof("Migration complete")
		log.Infof("Old keystore: %s", m.SrcKeyStoreParams().KeyDir())
		log.Infof("New keystore: %s", m.DstKeyStoreParams().KeyDir())
		if m.DryRun() {
			log.Infof("Run without --dry_run to actually write key data")
		}
		return
	}

	log.WithFields(log.Fields{"src": m.SrcKeyStoreVersion(), "dst": m.DstKeyStoreVersion()}).
		Fatal("Keystore conversion not supported")
}

// MigrateV1toV2 transfers keys from key store v1 to v2.
func MigrateV1toV2(srcV1 filesystemV1.KeyExport, dstV2 keystoreV2.KeyFileImportV1) error {
	log.Trace("Enumerating keys for export")
	keys, err := filesystemV1.EnumerateExportedKeys(srcV1)
	if err != nil {
		log.WithError(err).Debug("Failed to enumerate exported keys")
		return err
	}
	log.Trace("Key enumeration complete")

	// We are going to import multiple keys. Some of them may not be successful.
	// Since we cannot rollback partial import, go on with processing remaining
	// keys on error. However, make sure that the operation as a whole fails if
	// not all keys have been imported successfully.
	actual := 0
	expected := len(keys)

	log.Tracef("Importing %d keys from keystore v1", expected)
	for _, key := range keys {
		log := log.WithField("purpose", key.Purpose).WithField("id", key.ID)
		err := dstV2.ImportKeyFileV1(srcV1, key)
		if err != nil {
			log.WithError(err).Warn("Failed to import key")
			continue
		}
		actual++
	}
	log.Tracef("Imported %d/%d keys from keystore v1", actual, expected)

	if actual != expected {
		return errors.New("Incomplete key import")
	}

	return nil
}

func (m *MigrateKeysSubcommand) openKeyStoreV1(keyVarName string, params KeyStoreParameters) (*filesystemV1.KeyStore, error) {
	masterKey, err := keystoreV1.GetMasterKeyFromEnvironmentVariable(keyVarName)
	if err != nil {
		log.WithError(err).Error("Cannot load master key")
		return nil, err
	}
	encryptor, err := keystoreV1.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithError(err).Error("Cannot init Secure Cell encryptor")
		return nil, err
	}
	keyDir := params.KeyDir()
	keyDirPublic := params.KeyDirPublic()
	var keyStore *filesystemV1.KeyStore
	if keyDir != keyDirPublic {
		keyStore, err = filesystemV1.NewFilesystemKeyStoreTwoPath(keyDir, keyDirPublic, encryptor)
	} else {
		keyStore, err = filesystemV1.NewFilesystemKeyStore(keyDir, encryptor)
	}
	if err != nil {
		log.WithError(err).Error("Cannot init keystore")
		return nil, err
	}
	return keyStore, nil
}

func (m *MigrateKeysSubcommand) openKeyStoreV2(keyVarName string, params KeyStoreParameters) (*keystoreV2.ServerKeyStore, error) {
	encryption, signature, err := keystoreV2.GetMasterKeysFromEnvironmentVariable(keyVarName)
	if err != nil {
		log.WithError(err).Error("Cannot load master key")
		return nil, err
	}
	suite, err := keystoreV2.NewSCellSuite(encryption, signature)
	if err != nil {
		log.WithError(err).Error("Failed to initialize Secure Cell crypto suite")
		return nil, err
	}
	keyDirPath := params.KeyDir()
	if filesystemV2.IsKeyDirectory(keyDirPath) && !m.ForceWrite() {
		log.WithField("path", keyDirPath).Error("Key directory already exists")
		log.Info("Run with --force to import into existing directory")
		return nil, errors.New("destination exists")
	}
	var keyDir keystoreAPIV2.MutableKeyStore
	if m.DryRun() {
		keyDir, err = filesystemV2.NewInMemory(suite)
		if err != nil {
			log.WithError(err).Error("Cannot create in-memory keystore")
			return nil, err
		}
	} else {
		keyDir, err = filesystemV2.OpenDirectoryRW(keyDirPath, suite)
		if err != nil {
			log.WithError(err).WithField("path", keyDirPath).Error("Cannot open key directory")
			return nil, err
		}
	}
	return keystoreV2.NewServerKeyStore(keyDir), nil
}
