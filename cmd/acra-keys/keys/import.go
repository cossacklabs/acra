package keys

import (
	"flag"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
)

// ImportKeysParams are parameters of "acra-keys import" subcommand.
type ImportKeysParams interface {
	keystore.Importer
	ExportImportCommonParams
	ListKeysParams
}

// ImportKeysSubcommand is the "acra-keys import" subcommand.
type ImportKeysSubcommand struct {
	CommonKeyStoreParameters
	CommonExportImportParameters
	CommonKeyListingParameters
	FlagSet  *flag.FlagSet
	importer keystore.Importer
}

// Import implements keystore.Importer interface
func (p *ImportKeysSubcommand) Import(backup *keystore.KeysBackup) ([]keystore.KeyDescription, error) {
	return p.importer.Import(backup)
}

// Name returns the same of this subcommand.
func (p *ImportKeysSubcommand) Name() string {
	return CmdImportKeys
}

// GetFlagSet returns flag set of this subcommand.
func (p *ImportKeysSubcommand) GetFlagSet() *flag.FlagSet {
	return p.FlagSet
}

// RegisterFlags registers command-line flags of "acra-keys import".
func (p *ImportKeysSubcommand) RegisterFlags() {
	p.FlagSet = flag.NewFlagSet(CmdImportKeys, flag.ContinueOnError)
	p.CommonKeyStoreParameters.Register(p.FlagSet)
	p.CommonExportImportParameters.Register(p.FlagSet, "input")
	p.CommonKeyListingParameters.Register(p.FlagSet)
	network.RegisterTLSBaseArgs(p.FlagSet)
	p.FlagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": import keys into the keystore\n", CmdImportKeys)
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

// Execute this subcommand.
func (p *ImportKeysSubcommand) Execute() {
	var err error
	if IsKeyStoreV2(p) {
		var keyStore api.BackupKeystore
		keyStore, err = openKeyStoreV2(p)

		backuper, err := keystoreV2.NewKeyBackuper(p.keyDirPublic, p.keyDir, keyStore)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize backuper")
			os.Exit(1)
		}

		p.importer = backuper
	} else {
		var storage filesystem.Storage
		if redis := cmd.ParseRedisCLIParameters(); redis.KeysConfigured() {
			storage, err = filesystem.NewRedisStorage(redis.HostPort, redis.Password, redis.DBKeys, nil)
			if err != nil {
				log.WithError(err).Errorln("Can't initialize redis storage")
				os.Exit(1)
			}
		} else {
			storage = &filesystem.DummyStorage{}
		}

		keyStoreEncryptor, err := keyloader.CreateKeyEncryptor(p.FlagSet, "")
		if err != nil {
			log.WithError(err).Errorln("Can't init keystore KeyEncryptor")
			os.Exit(1)
		}

		backuper, err := filesystem.NewKeyBackuper(p.keyDir, p.keyDirPublic, storage, keyStoreEncryptor, nil)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize backuper")
			os.Exit(1)
		}

		p.importer = backuper
	}
	ImportKeysCommand(p)
}

// ImportKeysCommand implements the "import" command.
func ImportKeysCommand(params ImportKeysParams) {
	exportedKeyData, err := os.ReadFile(params.ExportDataFile())
	if err != nil {
		log.WithField("path", params.ExportDataFile()).WithError(err).Fatal("Failed to read data file")
	}

	importEncryptionKeyData, err := os.ReadFile(params.ExportKeysFile())
	if err != nil {
		log.WithField("path", params.ExportKeysFile()).WithError(err).Fatal("Failed to read key file")
	}
	defer utils.ZeroizeSymmetricKey(importEncryptionKeyData)

	keysBackup := keystore.KeysBackup{
		Keys: importEncryptionKeyData,
		Data: exportedKeyData,
	}

	descriptions, err := params.Import(&keysBackup)
	if err != nil {
		log.WithError(err).Fatal("Failed to import keys")
	}
	log.Infof("Successfully imported %d keys", len(descriptions))

	err = PrintKeys(descriptions, os.Stdout, params)
	if err != nil {
		log.WithError(err).Fatal("Failed to print imported key list")
	}
}
