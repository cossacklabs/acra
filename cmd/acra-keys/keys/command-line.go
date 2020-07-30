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

	"github.com/cossacklabs/acra/cmd"
	keystoreV1 "github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

// ServiceName constant for logging and configuration parsing.
const ServiceName = "acra-keys"

// DefaultKeyDirectory is the default path to key directory.
const DefaultKeyDirectory = keystoreV1.DefaultKeyDirShort

// DefaultConfigPath is the default path to service configuration file.
var DefaultConfigPath = utils.GetConfigPathByName("acra-keys")

// Sub-command names:
const (
	CmdListKeys   = "list"
	CmdExportKeys = "export"
	CmdImportKeys = "import"
	CmdReadKey    = "read"
	CmdDestroyKey = "destroy"
)

// SupportedSubCommands lists supported sub-commands or CLI.
var SupportedSubCommands = []string{
	CmdListKeys,
	CmdExportKeys,
	CmdImportKeys,
	CmdReadKey,
	CmdDestroyKey,
}

// Key kind constants:
const (
	KeyPoisonPublic   = "poison-public"
	KeyPoisonPrivate  = "poison-private"
	KeyStoragePublic  = "storage-public"
	KeyStoragePrivate = "storage-private"
	KeyZonePublic     = "zone-public"
	KeyZonePrivate    = "zone-private"

	KeyTransportConnector  = "transport-connector"
	KeyTransportServer     = "transport-server"
	KeyTransportTranslator = "transport-translator"
)

// Comman-line parsing errors:
var (
	ErrUnknownSubCommand = errors.New("unknown command")
	ErrMissingKeyKind    = errors.New("missing key kind")
	ErrMissingKeyID      = errors.New("missing key IDs")
	ErrMultipleKeyKinds  = errors.New("multiple key kinds")
	ErrMissingOutputFile = errors.New("output file not specified")
	ErrOutputSame        = errors.New("output files are the same")
)

// CommandLineParams describes all command-line options of acra-keys.
type CommandLineParams struct {
	keyDir       string
	keyDirPublic string

	clientID string
	zoneID   string

	Command string

	readKeyKind    string
	destroyKeyKind string

	exportIDs      []string
	exportAll      bool
	exportDataFile string
	exportKeysFile string
	exportPrivate  bool

	useJSON bool

	exportFlags  *flag.FlagSet
	importFlags  *flag.FlagSet
	listFlags    *flag.FlagSet
	readFlags    *flag.FlagSet
	destroyFlags *flag.FlagSet
}

// Params provide global access to command-line parameters.
var Params *CommandLineParams = &CommandLineParams{}

// Register configures command-line parameter parsing.
func (params *CommandLineParams) Register() {
	flag.StringVar(&params.keyDir, "keys_dir", DefaultKeyDirectory, "path to key directory")
	flag.StringVar(&params.keyDirPublic, "keys_dir_public", "", "path to key directory for public keys")
	flag.StringVar(&params.clientID, "client_id", "", "client ID for which to retrieve key")
	flag.StringVar(&params.zoneID, "zone_id", "", "zone ID for which to retrieve key")
	flag.BoolVar(&params.useJSON, "json", false, "use machine-readable JSON output")

	params.listFlags = flag.NewFlagSet(CmdListKeys, flag.ContinueOnError)
	params.listFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": list available keys in the key store\n", CmdListKeys)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...]\n", os.Args[0], CmdListKeys)
	}

	params.exportFlags = flag.NewFlagSet(CmdListKeys, flag.ContinueOnError)
	params.exportFlags.BoolVar(&params.exportAll, "all", false, "export all keys")
	params.exportFlags.StringVar(&params.exportDataFile, "key_bundle_file", "", "path to output file for exported key bundle")
	params.exportFlags.StringVar(&params.exportKeysFile, "key_bundle_secret", "", "path to output file for key encryption keys")
	params.exportFlags.BoolVar(&params.exportPrivate, "private_keys", false, "export private key data")
	params.exportFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": export keys from the key store\n", CmdExportKeys)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...] --key_bundle_file <file> --key_bundle_secret <file> <key-ID...>\n", os.Args[0], CmdExportKeys)
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(params.exportFlags)
	}

	params.importFlags = flag.NewFlagSet(CmdListKeys, flag.ContinueOnError)
	params.importFlags.StringVar(&params.exportDataFile, "key_bundle_file", "", "path to input file with exported key bundle")
	params.importFlags.StringVar(&params.exportKeysFile, "key_bundle_secret", "", "path to input file with key encryption keys")
	params.importFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": import keys into the key store\n", CmdImportKeys)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...] --key_bundle_file <file> --key_bundle_secret <file>\n", os.Args[0], CmdImportKeys)
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(params.importFlags)
	}

	params.readFlags = flag.NewFlagSet(CmdReadKey, flag.ContinueOnError)
	params.readFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": read and print key material in plaintext\n", CmdReadKey)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...] <key-kind>\n\n", os.Args[0], CmdReadKey)
		fmt.Fprintf(os.Stderr, "Supported key kinds:\n  %s\n", strings.Join(SupportedReadKeyKinds, ", "))
	}

	params.destroyFlags = flag.NewFlagSet(CmdDestroyKey, flag.ContinueOnError)
	params.destroyFlags.StringVar(&params.clientID, "client_id", "", "client ID for which to destroy key")
	params.destroyFlags.StringVar(&params.zoneID, "zone_id", "", "zone ID for which to destroy key")
	params.destroyFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": destroy key material\n", CmdDestroyKey)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...] <key-kind>\n\n", os.Args[0], CmdDestroyKey)
		fmt.Fprintf(os.Stderr, "Supported key kinds:\n  %s\n", strings.Join(SupportedDestroyKeyKinds, ", "))
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n\t%s [options...] <command> [arguments...]\n", os.Args[0])

	fmt.Fprintf(os.Stderr, "\nGlobal options:\n")
	cmd.PrintFlags(flag.CommandLine)

	fmt.Fprintf(os.Stderr, "\n")
	Params.listFlags.Usage()

	fmt.Fprintf(os.Stderr, "\n")
	Params.exportFlags.Usage()

	fmt.Fprintf(os.Stderr, "\n")
	Params.importFlags.Usage()

	fmt.Fprintf(os.Stderr, "\n")
	Params.readFlags.Usage()

	fmt.Fprintf(os.Stderr, "\n")
	Params.destroyFlags.Usage()
}

// KeyDir returns path to key directory.
func (params *CommandLineParams) KeyDir() string {
	return params.keyDir
}

// KeyDirPublic returns path to public key directory (if different from key directory).
func (params *CommandLineParams) KeyDirPublic() string {
	return params.keyDirPublic
}

// UseJSON tells if machine-readable JSON should be used.
func (params *CommandLineParams) UseJSON() bool {
	return params.useJSON
}

//ExportIDs returns key IDs to export.
func (params *CommandLineParams) ExportIDs() []string {
	return params.exportIDs
}

//ExportAll returns true if all keys should be exported, regardless of ExportIDs() value.
func (params *CommandLineParams) ExportAll() bool {
	return params.exportAll
}

// ExportPrivate returns true if private keys should be included into exported data.
func (params *CommandLineParams) ExportPrivate() bool {
	return params.exportPrivate
}

// ExportKeysFile returns path to file with encryption keys for export.
func (params *CommandLineParams) ExportKeysFile() string {
	return params.exportKeysFile
}

// ExportDataFile returns path to file with encrypted exported key data.
func (params *CommandLineParams) ExportDataFile() string {
	return params.exportDataFile
}

// ReadKeyKind returns kind of the requested key.
func (params *CommandLineParams) ReadKeyKind() string {
	return params.readKeyKind
}

// ClientID returns client ID of the requested key.
func (params *CommandLineParams) ClientID() []byte {
	return []byte(params.clientID)
}

// ZoneID returns zone ID of the requested key.
func (params *CommandLineParams) ZoneID() []byte {
	return []byte(params.zoneID)
}

// DestroyKeyKind returns requested kind of the key to destroy.
func (params *CommandLineParams) DestroyKeyKind() string {
	return params.destroyKeyKind
}

// Parse parses complete command-line.
func (params *CommandLineParams) Parse() error {
	err := cmd.Parse(DefaultConfigPath, ServiceName)
	if err != nil {
		return err
	}
	err = params.ParseSubCommand()
	if err != nil {
		return err
	}
	return nil
}

// ParseSubCommand parses sub-command and its arguments.
func (params *CommandLineParams) ParseSubCommand() error {
	args := flag.Args()
	if len(args) == 0 {
		log.WithField("supported", SupportedSubCommands).
			Info("No command specified")
		return nil
	}
	params.Command = args[0]
	switch args[0] {
	case CmdListKeys:
		return nil

	case CmdExportKeys:
		err := params.exportFlags.Parse(args[1:])
		if err != nil {
			return err
		}

		if params.exportDataFile == "" || params.exportKeysFile == "" {
			log.Errorf("\"%s\" command requires output files specified with \"--key_bundle_file\" and \"--key_bundle_secret\"", CmdExportKeys)
			return ErrMissingOutputFile
		}
		// We do not account for people getting creative with ".." and links.
		if params.exportDataFile == params.exportKeysFile {
			log.Errorf("\"--key_bundle_file\" and \"--key_bundle_secret\" must not be the same file")
			return ErrOutputSame
		}

		args := params.exportFlags.Args()
		if len(args) < 1 && !params.exportAll {
			log.Errorf("\"%s\" command requires at least one key ID", CmdExportKeys)
			log.Infoln("Use \"--all\" to export all keys")
			return ErrMissingKeyID
		}
		params.exportIDs = args
		return nil

	case CmdImportKeys:
		err := params.importFlags.Parse(args[1:])
		if err != nil {
			return err
		}
		if params.exportDataFile == "" || params.exportKeysFile == "" {
			log.Errorf("\"%s\" command requires input files specified with \"--key_bundle_file\" and \"--key_bundle_secret\"", CmdImportKeys)
			return ErrMissingOutputFile
		}
		return nil

	case CmdReadKey:
		err := params.readFlags.Parse(args[1:])
		if err != nil {
			return err
		}
		args := params.readFlags.Args()
		if len(args) < 1 {
			log.Errorf("\"%s\" command requires key kind", CmdReadKey)
			return ErrMissingKeyKind
		}
		// It makes sense to allow multiple keys, but we can't think of a useful
		// output format for that, so we currently don't allow it.
		if len(args) > 1 {
			log.Errorf("\"%s\" command does not support more than one key kind", CmdReadKey)
			return ErrMultipleKeyKinds
		}
		params.readKeyKind = args[0]
		return params.CheckForKeyKind(params.readKeyKind)

	case CmdDestroyKey:
		err := params.destroyFlags.Parse(args[1:])
		if err != nil {
			return err
		}
		args := params.destroyFlags.Args()
		if len(args) < 1 {
			log.Errorf("\"%s\" command requires key kind", CmdDestroyKey)
			return ErrMissingKeyKind
		}
		// It makes sense to allow multiple keys, but we can't think of a useful
		// output format for that, so we currently don't allow it.
		if len(args) > 1 {
			log.Errorf("\"%s\" command does not support more than one key kind", CmdDestroyKey)
			return ErrMultipleKeyKinds
		}
		params.destroyKeyKind = args[0]
		return params.CheckForKeyKind(params.destroyKeyKind)

	default:
		log.WithField("expected", SupportedSubCommands).
			Errorf("Unknown command: %s", args[0])
		return ErrUnknownSubCommand
	}
}

// SetDefaults sets dynamically configured default values of command-line parameters.
func (params *CommandLineParams) SetDefaults() {
	if params.keyDirPublic == "" {
		params.keyDirPublic = params.keyDir
	}
}

// Check command-line for consistency. Exit the process on error.
func (params *CommandLineParams) Check() {
	if params.clientID != "" && params.zoneID != "" {
		log.Fatal("--client_id and --zone_id cannot be used simultaneously")
	}

	if params.readKeyKind != "" && params.destroyKeyKind != "" {
		log.Fatal("--read_key and --destroy_key cannot be used simultaneously")
	}
}

// CheckForKeyKind check options required by specified key kind
func (params *CommandLineParams) CheckForKeyKind(keyKind string) error {
	switch keyKind {
	case KeyTransportConnector, KeyTransportServer, KeyTransportTranslator, KeyStoragePublic, KeyStoragePrivate:
		if params.clientID == "" {
			log.Errorf("\"%s\" key requires --client_id", keyKind)
			return ErrMissingClientID
		}
	case KeyZonePublic, KeyZonePrivate:
		if Params.zoneID == "" {
			log.Errorf("\"%s\" key requires --zone_id", keyKind)
			return ErrMissingZoneID
		}
	}
	return nil
}

// ParseParams will parse complete command-line and fill in `Params` values.
// It will exit on any issues with the configuration.
func ParseParams() {
	flag.CommandLine.Usage = usage

	Params.Register()

	err := Params.Parse()
	if err == flag.ErrHelp {
		os.Exit(0)
	}
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Fatal("Cannot parse arguments")
	}

	Params.SetDefaults()
	Params.Check()
}
