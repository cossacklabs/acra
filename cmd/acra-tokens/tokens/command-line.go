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

// Package tokens defines reusable business logic of "acra-tokens" utility.
package tokens

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
)

// ServiceName constant for logging and configuration parsing.
const ServiceName = "acra-tokens"

// DefaultConfigPath is the default path to service configuration file.
var DefaultConfigPath = utils.GetConfigPathByName(ServiceName)

// Comman-line parsing errors:
var (
	ErrUnknownSubCommand = errors.New("unknown command")
)

// Subcommand is "acra-tokens" subcommand.
type Subcommand interface {
	Name() string
	RegisterFlags()
	FlagSet() *flag.FlagSet
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
	err := cmd.ParseFlags(flag.CommandLine, os.Args[1:])
	// If there is "--dump_config" on the command line,
	// dump configuration for all subcommand and immediately exit.
	if err == cmd.ErrDumpRequested {
		flagSets := make([]*flag.FlagSet, len(subcommands)+1)
		flagSets[0] = flag.CommandLine
		for i, command := range subcommands {
			flagSets[i+1] = command.FlagSet()
		}
		cmd.DumpConfigFromFlagSets(flagSets, DefaultConfigPath, ServiceName, true)
		os.Exit(0)
	}
	if err != nil {
		return nil, err
	}
	_, err = cmd.ParseConfig(DefaultConfigPath, ServiceName)
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
