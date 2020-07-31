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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

// ExportKeyPerm is file permissions required for exported key data.
const ExportKeyPerm = os.FileMode(0600)

// Key export errors:
var (
	ErrIncorrectPerm = errors.New("incorrect output file permissions")
)

type serializedKeys struct {
	Encryption []byte `json:"encryption"`
	Signature  []byte `json:"signature"`
}

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

// Register registers key store flags with the given flag set.
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
	ExportImportCommonParams
	ExportIDs() []string
	ExportAll() bool
	ExportPrivate() bool
}

// ExportKeysSubcommand is the "acra-keys export" subcommand.
type ExportKeysSubcommand struct {
	CommonKeyStoreParameters
	CommonExportImportParameters
	FlagSet *flag.FlagSet

	exportIDs     []string
	exportAll     bool
	exportPrivate bool
}

// Name returns the same of this subcommand.
func (p *ExportKeysSubcommand) Name() string {
	return CmdExportKeys
}

// RegisterFlags registers command-line flags of "acra-keys export".
func (p *ExportKeysSubcommand) RegisterFlags() {
	p.FlagSet = flag.NewFlagSet(CmdExportKeys, flag.ContinueOnError)
	p.CommonKeyStoreParameters.Register(p.FlagSet)
	p.CommonExportImportParameters.Register(p.FlagSet, "output")
	p.FlagSet.BoolVar(&p.exportAll, "all", false, "export all keys")
	p.FlagSet.BoolVar(&p.exportPrivate, "private_keys", false, "export private key data")
	p.FlagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": export keys from the key store\n", CmdExportKeys)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...] --key_bundle_file <file> --key_bundle_secret <file> <key-ID...>\n", os.Args[0], CmdExportKeys)
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(p.FlagSet)
	}
}

// Parse command-line parameters of the subcommand.
func (p *ExportKeysSubcommand) Parse(arguments []string) error {
	err := cmd.ParseFlagsWithConfig(p.FlagSet, arguments, DefaultConfigPath, ServiceName)
	if err != nil {
		return err
	}
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
	p.exportIDs = args
	return nil
}

// ExportIDs returns key IDs to export.
func (p *ExportKeysSubcommand) ExportIDs() []string {
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

// ImportKeysParams are parameters of "acra-keys import" subcommand.
type ImportKeysParams interface {
	ExportImportCommonParams
	ListKeysParams
}

// ImportKeysSubcommand is the "acra-keys import" subcommand.
type ImportKeysSubcommand struct {
	CommonKeyStoreParameters
	CommonExportImportParameters
	CommonKeyListingParameters
	FlagSet *flag.FlagSet
}

// Name returns the same of this subcommand.
func (p *ImportKeysSubcommand) Name() string {
	return CmdImportKeys
}

// RegisterFlags registers command-line flags of "acra-keys import".
func (p *ImportKeysSubcommand) RegisterFlags() {
	p.FlagSet = flag.NewFlagSet(CmdImportKeys, flag.ContinueOnError)
	p.CommonKeyStoreParameters.Register(p.FlagSet)
	p.CommonExportImportParameters.Register(p.FlagSet, "input")
	p.CommonKeyListingParameters.Register(p.FlagSet)
	p.FlagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": import keys into the key store\n", CmdImportKeys)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...] --key_bundle_file <file> --key_bundle_secret <file>\n", os.Args[0], CmdImportKeys)
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(p.FlagSet)
	}
}

// Parse command-line parameters of the subcommand.
func (p *ImportKeysSubcommand) Parse(arguments []string) error {
	err := cmd.ParseFlagsWithConfig(p.FlagSet, arguments, DefaultConfigPath, ServiceName)
	if err != nil {
		return err
	}
	err = p.CommonExportImportParameters.validate()
	if err != nil {
		return err
	}
	return nil
}

// PrepareExportEncryptionKeys generates new ephemeral keys for key export operation.
func PrepareExportEncryptionKeys() ([]byte, *crypto.KeyStoreSuite, error) {
	encryptionKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		log.WithError(err).Debug("Failed to generate symmetric key")
		return nil, nil, err
	}

	signatureKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		log.WithError(err).Debug("Failed to generate symmetric key")
		return nil, nil, err
	}

	serializedKeys, err := json.Marshal(&serializedKeys{Encryption: encryptionKey, Signature: signatureKey})
	if err != nil {
		log.WithError(err).Debug("Failed to serialize keys in JSON")
		return nil, nil, err
	}

	// We do not zeroize the keys since a) they are stored by reference in the cryptosuite,
	// b) they have not been used to encrypt anything yet.
	cryptosuite, err := crypto.NewSCellSuite(encryptionKey, signatureKey)
	if err != nil {
		log.WithError(err).Debug("Failed to setup cryptosuite")
		return nil, nil, err
	}

	return serializedKeys, cryptosuite, nil
}

// ReadImportEncryptionKeys reads ephemeral keys for key import operation.
func ReadImportEncryptionKeys(params ExportImportCommonParams) (*crypto.KeyStoreSuite, error) {
	keysFile := params.ExportKeysFile()
	importEncryptionKeyData, err := ioutil.ReadFile(keysFile)
	if err != nil {
		log.WithField("path", keysFile).WithError(err).Debug("Failed to read key file")
		return nil, err
	}
	defer utils.ZeroizeSymmetricKey(importEncryptionKeyData)

	var importEncryptionKeys serializedKeys
	err = json.Unmarshal(importEncryptionKeyData, &importEncryptionKeys)
	if err != nil {
		log.WithField("path", keysFile).WithError(err).Debug("Failed to parse key file content")
		return nil, err
	}

	cryptosuite, err := crypto.NewSCellSuite(importEncryptionKeys.Encryption, importEncryptionKeys.Signature)
	if err != nil {
		log.WithField("path", keysFile).WithError(err).Debug("Failed to initialize cryptosuite")
		return nil, err
	}

	return cryptosuite, nil
}

// ExportKeys exports requested key rings.
func ExportKeys(keyStore api.KeyStore, cryptosuite *crypto.KeyStoreSuite, params ExportKeysParams) (exportedData []byte, err error) {
	exportedIDs := params.ExportIDs()
	if params.ExportAll() {
		exportedIDs, err = keyStore.ListKeyRings()
		if err != nil {
			log.WithError(err).Debug("Failed to list available keys")
			return nil, err
		}
	}

	mode := api.ExportPublicOnly
	if params.ExportPrivate() {
		mode = api.ExportPrivateKeys
	}
	exportedData, err = keyStore.ExportKeyRings(exportedIDs, cryptosuite, mode)
	if err != nil {
		log.WithError(err).Debug("Failed to export key rings")
		return nil, err
	}
	return exportedData, nil
}

// ImportKeys imports available key rings.
func ImportKeys(exportedData []byte, keyStore api.MutableKeyStore, cryptosuite *crypto.KeyStoreSuite, params ImportKeysParams) ([]keystore.KeyDescription, error) {
	keyIDs, err := keyStore.ImportKeyRings(exportedData, cryptosuite, nil)
	if err != nil {
		log.WithError(err).Debug("Failed to import key rings")
		return nil, err
	}
	descriptions, err := keystoreV2.DescribeKeyRings(keyIDs, keyStore)
	if err != nil {
		log.WithError(err).Debug("Failed to describe imported key rings")
		return nil, err
	}
	return descriptions, nil
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

// ReadExportedData reads exported key data from designated file.
func ReadExportedData(params ExportImportCommonParams) ([]byte, error) {
	dataFile := params.ExportDataFile()
	exportedKeyData, err := ioutil.ReadFile(dataFile)
	if err != nil {
		log.WithField("path", dataFile).WithError(err).Debug("Failed to read data file")
		return nil, err
	}
	return exportedKeyData, nil
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
