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
	"flag"
	"fmt"
	"io"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils/args"
)

// ListKeysParams ara parameters of "acra-keys list" subcommand.
type ListKeysParams interface {
	UseJSON() bool
	ListRotatedKeys() bool
}

// CommonKeyListingParameters is a mix-in of command line parameters for keystore listing.
type CommonKeyListingParameters struct {
	useJSON     bool
	rotatedKeys bool
}

// UseJSON tells if machine-readable JSON should be used.
func (p *CommonKeyListingParameters) UseJSON() bool {
	return p.useJSON
}

// ListRotatedKeys return param if command should display rotated keys.
func (p *CommonKeyListingParameters) ListRotatedKeys() bool {
	return p.rotatedKeys
}

// Register registers key formatting flags with the given flag set.
func (p *CommonKeyListingParameters) Register(flags *flag.FlagSet) {
	flags.BoolVar(&p.useJSON, "json", false, "use machine-readable JSON output")
}

// ListKeySubcommand is the "acra-keys list" subcommand.
type ListKeySubcommand struct {
	CommonKeyStoreParameters
	CommonKeyListingParameters
	FlagSet   *flag.FlagSet
	extractor *args.ServiceExtractor
}

// GetExtractor return ServiceParamsExtractor
func (p *ListKeySubcommand) GetExtractor() *args.ServiceExtractor {
	return p.extractor
}

// Name returns the same of this subcommand.
func (p *ListKeySubcommand) Name() string {
	return CmdListKeys
}

// GetFlagSet returns flag set of this subcommand.
func (p *ListKeySubcommand) GetFlagSet() *flag.FlagSet {
	return p.FlagSet
}

// RegisterFlags registers command-line flags of "acra-keys list".
func (p *ListKeySubcommand) RegisterFlags() {
	p.FlagSet = flag.NewFlagSet(CmdListKeys, flag.ContinueOnError)
	p.CommonKeyStoreParameters.Register(p.FlagSet)
	p.CommonKeyListingParameters.Register(p.FlagSet)
	network.RegisterTLSBaseArgs(p.FlagSet)
	p.FlagSet.BoolVar(&p.rotatedKeys, "rotated-keys", false, "List rotated keys")
	p.FlagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": list available keys in the keystore\n", CmdListKeys)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...]\n", os.Args[0], CmdListKeys)
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(p.FlagSet)
	}
}

// Parse command-line parameters of the subcommand.
func (p *ListKeySubcommand) Parse(arguments []string) error {
	if err := cmd.ParseFlags(p.FlagSet, arguments); err != nil {
		return err
	}

	serviceConfig, err := cmd.ParseConfig(DefaultConfigPath, ServiceName)
	if err != nil {
		return err
	}

	p.extractor = args.NewServiceExtractor(p.FlagSet, serviceConfig)
	return nil
}

// Execute this subcommand.
func (p *ListKeySubcommand) Execute() {
	keyStore, err := OpenKeyStoreForReading(p)
	if err != nil {
		log.WithError(err).Fatal("Failed to open keystore")
	}
	ListKeysCommand(p, keyStore)
}

// ListKeysCommand implements the "list" command.
func ListKeysCommand(params ListKeysParams, keyStore keystore.ServerKeyStore) {
	keyDescriptions, err := keyStore.ListKeys()
	if err != nil {
		log.WithError(err).Fatal("Failed to read key list")
	}

	var rotatedDescriptions []keystore.KeyDescription
	if params.ListRotatedKeys() {
		rotatedDescriptions, err = keyStore.ListRotatedKeys()
		if err != nil {
			log.WithError(err).Fatal("Failed to read rotated key list")
		}
	}

	if params.UseJSON() {
		keyDescriptions = append(keyDescriptions, rotatedDescriptions...)

		if err := printKeysJSON(keyDescriptions, os.Stdout); err != nil {
			log.WithError(err).Fatal("Failed to print key list in JSON")
		}
		return
	}

	// print current keys in table format
	err = keystore.PrintKeysTable(keyDescriptions, os.Stdout)
	if err != nil {
		log.WithError(err).Fatal("Failed to print key list")
	}

	if params.ListRotatedKeys() {
		// print rotated keys in table format
		err = keystore.PrintRotatedKeysTable(rotatedDescriptions, os.Stdout)
		if err != nil {
			log.WithError(err).Fatal("Failed to print list of rotated keys")
		}
	}
}

// PrintKeys prints key list prettily into the given writer.
func PrintKeys(keys []keystore.KeyDescription, writer io.Writer, params ListKeysParams) error {
	if params.UseJSON() {
		return printKeysJSON(keys, writer)
	}
	return keystore.PrintKeysTable(keys, writer)
}

func printKeysJSON(keys []keystore.KeyDescription, writer io.Writer) error {
	json, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	json = append(json, byte('\n'))
	_, err = writer.Write(json)
	return err
}
