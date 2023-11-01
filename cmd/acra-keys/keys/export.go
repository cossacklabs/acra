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
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/cmd/args"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
)

// ExportKeyPerm is file permissions required for exported key data.
const ExportKeyPerm = os.FileMode(0600)

// Key export errors:
var (
	ErrIncorrectPerm = errors.New("incorrect output file permissions")
)

// ExportImportCommonParams are common parameters of "acra-keys export" and "acra-keys import" subcommand.
type ExportImportCommonParams interface {
	ExportKeysFile() string
	ExportDataFile() string
}

// CommonExportImportParameters are common parameters of "acra-keys export" and "acra-keys import" subcommand.
type CommonExportImportParameters struct {
	exportKeysFile string
	exportDataFile string
}

// ExportKeysFile returns path to file with encryption keys for export.
func (p *CommonExportImportParameters) ExportKeysFile() string {
	return p.exportKeysFile
}

// ExportDataFile returns path to file with encrypted exported key data.
func (p *CommonExportImportParameters) ExportDataFile() string {
	return p.exportDataFile
}

// Register registers keystore flags with the given flag set.
func (p *CommonExportImportParameters) Register(flags *flag.FlagSet, filePurspose string) {
	// The purpose is either "output" or "output". This is not very localizable, but we don't care about it at this point.
	flags.StringVar(&p.exportDataFile, "key_bundle_file", "", "path to "+filePurspose+" file for exported key bundle")
	flags.StringVar(&p.exportKeysFile, "key_bundle_secret", "", "path to "+filePurspose+" file for key encryption keys")
}

func (p *CommonExportImportParameters) validate() error {
	if p.exportDataFile == "" || p.exportKeysFile == "" {
		log.Errorf("\"--key_bundle_file\" and \"--key_bundle_secret\" options are required")
		return ErrMissingOutputFile
	}
	// We do not account for people getting creative with ".." and links.
	if p.exportDataFile == p.exportKeysFile {
		log.Errorf("\"--key_bundle_file\" and \"--key_bundle_secret\" must not be the same file")
		return ErrOutputSame
	}
	return nil
}

// ExportKeysParams are parameters of "acra-keys export" subcommand.
type ExportKeysParams interface {
	keystore.Exporter
	ExportImportCommonParams
	ExportIDs() []keystore.ExportID
	ExportAll() bool
	ExportPrivate() bool
}

// ExportKeysSubcommand is the "acra-keys export" subcommand.
type ExportKeysSubcommand struct {
	CommonKeyStoreParameters
	CommonExportImportParameters
	FlagSet   *flag.FlagSet
	extractor *args.ServiceExtractor
	exporter  keystore.Exporter

	exportIDs     []keystore.ExportID
	exportAll     bool
	exportPrivate bool
}

// GetExtractor return ServiceParamsExtractor
func (p *ExportKeysSubcommand) GetExtractor() *args.ServiceExtractor {
	return p.extractor
}

// Name returns the same of this subcommand.
func (p *ExportKeysSubcommand) Name() string {
	return CmdExportKeys
}

// GetFlagSet returns flag set of this subcommand.
func (p *ExportKeysSubcommand) GetFlagSet() *flag.FlagSet {
	return p.FlagSet
}

// RegisterFlags registers command-line flags of "acra-keys export".
func (p *ExportKeysSubcommand) RegisterFlags() {
	p.FlagSet = flag.NewFlagSet(CmdExportKeys, flag.ContinueOnError)
	p.CommonKeyStoreParameters.Register(p.FlagSet)
	p.CommonExportImportParameters.Register(p.FlagSet, "output")
	network.RegisterTLSBaseArgs(p.FlagSet)
	p.FlagSet.BoolVar(&p.exportAll, "all", false, "export all keys")
	p.FlagSet.BoolVar(&p.exportPrivate, "private_keys", false, "export private key data (symmetric and private asymmetric keys)")
	p.FlagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": export keys from the keystore\n", CmdExportKeys)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...] --key_bundle_file <file> --key_bundle_secret <file> <key-ID...>\n", os.Args[0], CmdExportKeys)
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(p.FlagSet)
	}
}

// Parse command-line parameters of the subcommand.
func (p *ExportKeysSubcommand) Parse(arguments []string) error {
	err := cmd.ParseFlags(p.FlagSet, arguments)
	if err != nil {
		return err
	}

	serviceConfig, err := cmd.ParseConfig(DefaultConfigPath, ServiceName)
	if err != nil {
		return err
	}

	p.extractor = args.NewServiceExtractor(p.FlagSet, serviceConfig)
	err = p.CommonExportImportParameters.validate()
	if err != nil {
		return err
	}
	args := p.FlagSet.Args()
	if len(args) < 1 && !p.exportAll {
		log.Errorf("\"%s\" command requires at least one key ID", CmdExportKeys)
		log.Infoln("Use \"--all\" to export all keys")
		return ErrMissingKeyID
	}

	if !p.exportAll {
		for _, arg := range args {
			coarseKind, id, err := ParseKeyKind(arg)
			if err != nil {
				// for backward compatibility reasons we need to save ability to specify keys to export as key path
				// the example of the key path for V2 keystore - client/client_test/storage
				// we need to add .keyring suffix to determine key purpose
				if IsKeyStoreV2(p) && !strings.HasSuffix(arg, ".keyring") {
					arg += ".keyring"
				}

				description, err := filesystem.DescribeKeyFile(arg)
				if err != nil {
					log.WithField("key", arg).Fatal(err)
				}

				keyKind, ok := keystore.KeyPurposeToKeyKind[description.Purpose]
				if !ok {
					log.WithField("key", arg).Fatal("Unsupported key provided")
				}
				coarseKind = keyKind
				id = []byte(description.ClientID)
			}

			if (coarseKind == keystore.KeySymmetric || coarseKind == keystore.KeySearch) && !p.exportPrivate {
				log.Fatal("Export symmetric keys expect \"--private_keys\"")
			}

			switch coarseKind {
			case keystore.KeySymmetric:
				p.exportIDs = append(p.exportIDs, keystore.ExportID{
					KeyKind:   coarseKind,
					ContextID: id,
				})

			case keystore.KeyPoisonKeypair:
				if p.exportPrivate {
					p.exportIDs = append(p.exportIDs, keystore.ExportID{
						KeyKind: keystore.KeyPoisonPrivate,
					})
				} else {
					p.exportIDs = append(p.exportIDs, keystore.ExportID{
						KeyKind: keystore.KeyPoisonPublic,
					})
				}

			case keystore.KeyStorageKeypair:
				if p.exportPrivate {
					p.exportIDs = append(p.exportIDs, keystore.ExportID{
						KeyKind:   keystore.KeyStoragePrivate,
						ContextID: id,
					})
				} else {
					p.exportIDs = append(p.exportIDs, keystore.ExportID{
						KeyKind:   keystore.KeyStoragePublic,
						ContextID: id,
					})
				}

			case keystore.KeySearch:
				p.exportIDs = append(p.exportIDs, keystore.ExportID{
					KeyKind:   keystore.KeySearch,
					ContextID: id,
				})
			default:
				return ErrUnknownKeyKind
			}
		}
	}

	return nil
}

// Execute this subcommand.
func (p *ExportKeysSubcommand) Execute() {
	var err error
	if IsKeyStoreV2(p) {
		var keyStore api.BackupKeystore
		keyStore, err = openKeyStoreV2(p)
		if err != nil {
			log.WithError(err).Errorln("Can't open V2 keystore")
			os.Exit(1)
		}

		backuper, err := keystoreV2.NewKeyBackuper(p.keyDirPublic, p.keyDir, keyStore)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize backuper")
			os.Exit(1)
		}

		p.exporter = backuper
	} else {
		keyStore, err := openKeyStoreV1(p)
		if err != nil {
			log.WithError(err).Errorln("Can't open V1 keystore")
			os.Exit(1)
		}

		var storge filesystem.Storage
		if redis := cmd.ParseRedisCLIParameters(p.GetExtractor()); redis.KeysConfigured() {
			storge, err = filesystem.NewRedisStorage(redis.HostPort, redis.Password, redis.DBKeys, nil)
			if err != nil {
				log.WithError(err).Errorln("Can't initialize redis storage")
				os.Exit(1)
			}
		} else {
			storge = &filesystem.DummyStorage{}
		}

		keyStoreEncryptor, err := keyloader.CreateKeyEncryptor(p.GetExtractor(), "")
		if err != nil {
			log.WithError(err).Errorln("Can't init keystore KeyEncryptor")
			os.Exit(1)
		}

		backuper, err := filesystem.NewKeyBackuper(p.keyDir, p.keyDirPublic, storge, keyStoreEncryptor, keyStore)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize backuper")
			os.Exit(1)
		}

		p.exporter = backuper
	}

	ExportKeysCommand(p)
}

// ExportIDs returns key IDs to export.
func (p *ExportKeysSubcommand) ExportIDs() []keystore.ExportID {
	return p.exportIDs
}

// ExportAll returns true if all keys should be exported, regardless of ExportIDs() value.
func (p *ExportKeysSubcommand) ExportAll() bool {
	return p.exportAll
}

// ExportPrivate returns true if private keys should be included into exported data.
func (p *ExportKeysSubcommand) ExportPrivate() bool {
	return p.exportPrivate
}

// Export implements keystore.Exporter interface
func (p *ExportKeysSubcommand) Export(exportIDs []keystore.ExportID, mode keystore.ExportMode) (*keystore.KeysBackup, error) {
	return p.exporter.Export(exportIDs, mode)
}

// WriteExportedData saves exported key data and ephemeral keys into designated files.
func WriteExportedData(data, keys []byte, params ExportKeysParams) error {
	err := writeFileWithMode(data, params.ExportDataFile(), ExportKeyPerm)
	if err != nil {
		return err
	}
	err = writeFileWithMode(keys, params.ExportKeysFile(), ExportKeyPerm)
	if err != nil {
		return err
	}
	return nil
}

// ExportKeysCommand implements the "export" command.
func ExportKeysCommand(exporter ExportKeysParams) {
	var mode = keystore.ExportPublicOnly

	switch {
	case exporter.ExportPrivate():
		mode = keystore.ExportPrivateKeys
	case exporter.ExportAll():
		mode = keystore.ExportAllKeys
	}

	backup, err := exporter.Export(exporter.ExportIDs(), mode)
	if err != nil {
		log.WithError(err).Fatal("Failed to export keys")
	}

	err = WriteExportedData(backup.Data, backup.Keys, exporter)
	if err != nil {
		log.WithError(err).Fatal("Failed to write exported data")
	}

	log.Infof("Exported key data is encrypted and saved here: %s", exporter.ExportDataFile())
	log.Infof("New encryption keys for import generated here: %s", exporter.ExportKeysFile())
	log.Infof("DO NOT transport or store these files together")
	log.Infof("Import the keys into another keystore like this:\n\tacra-keys import --key_bundle_file \"%s\" --key_bundle_secret \"%s\"", exporter.ExportDataFile(), exporter.ExportKeysFile())
}

func writeFileWithMode(data []byte, path string, perm os.FileMode) (err error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		log.WithField("path", path).WithError(err).Debug("Failed to open file")
		return err
	}
	defer func() {
		if err2 := file.Close(); err2 != nil {
			log.WithField("path", path).WithError(err2).Debug("Failed to close file")
			if err != nil {
				err = err2
			}
		}
	}()

	fi, err := file.Stat()
	if err != nil {
		log.WithField("path", path).WithError(err).Debug("Failed to stat file")
		return err
	}
	if fi.Mode().Perm() != ExportKeyPerm {
		log.WithField("path", path).WithField("expected", ExportKeyPerm).WithField("actual", fi.Mode().Perm()).
			Error("Incorrect output file permissions")
		return ErrIncorrectPerm
	}

	_, err = utils.WriteFull(data, file)
	return err
}
