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
	CmdListKeys    = "list"
	CmdExportKeys  = "export"
	CmdImportKeys  = "import"
	CmdMigrateKeys = "migrate"
	CmdReadKey     = "read"
	CmdDestroyKey  = "destroy"
)

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

// Subcommand is "acra-keys" subcommand, like "acra-keys export".
type Subcommand interface {
	Name() string
	RegisterFlags()
	GetFlagSet() *flag.FlagSet
	Parse(arguments []string) error
	Execute()
}

// ParseParameters parses command-line parameters and returns the selected subcommand.
// There may be no subcommand selected, in which case nil is returned.
// It terminates the process on error.
func ParseParameters(subcommands []Subcommand) Subcommand {
	flag.CommandLine.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n\t%s [options...] <command> [arguments...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nGlobal options:\n")
		cmd.PrintFlags(flag.CommandLine)
		names := make([]string, len(subcommands))
		for i, c := range subcommands {
			names[i] = c.Name()
		}
		fmt.Fprintf(os.Stderr, "\nSupported commands:\n  %s\n", strings.Join(names, ", "))
	}
	for _, c := range subcommands {
		c.RegisterFlags()
	}

	subcommand, err := parseParameters(subcommands)
	if err == flag.ErrHelp {
		os.Exit(0)
	}
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Fatal("Cannot parse arguments")
	}
	return subcommand
}

func parseParameters(subcommands []Subcommand) (Subcommand, error) {
	err := cmd.ParseFlagsWithConfig(flag.CommandLine, os.Args[1:], DefaultConfigPath, ServiceName)
	// If there is "--dump_config" on the command line,
	// dump configuration for all subcommand and immediately exit.
	if err == cmd.ErrDumpRequested {
		flagSets := make([]*flag.FlagSet, len(subcommands)+1)
		flagSets[0] = flag.CommandLine
		for i, command := range subcommands {
			flagSets[i+1] = command.GetFlagSet()
		}
		cmd.DumpConfigFromFlagSets(flagSets, DefaultConfigPath, ServiceName, true)
		os.Exit(0)
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, len(subcommands))
	for i, command := range subcommands {
		names[i] = command.Name()
	}
	args := flag.CommandLine.Args()
	if len(args) == 0 {
		log.WithField("supported", names).Info("No command specified")
		return nil, nil
	}
	subcommandName := args[0]
	for _, c := range subcommands {
		if c.Name() == subcommandName {
			err = c.Parse(args[1:])
			if err != nil {
				return c, err
			}
			return c, nil
		}
	}
	log.WithField("expected", names).Errorf("Unknown command: %s", subcommandName)
	return nil, ErrUnknownSubCommand
}
