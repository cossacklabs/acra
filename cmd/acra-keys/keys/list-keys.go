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

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	log "github.com/sirupsen/logrus"
)

// ListKeysParams ara parameters of "acra-keys list" subcommand.
type ListKeysParams interface {
	UseJSON() bool
}

// CommonKeyListingParameters is a mix-in of command line parameters for keystore listing.
type CommonKeyListingParameters struct {
	useJSON bool
}

// UseJSON tells if machine-readable JSON should be used.
func (p *CommonKeyListingParameters) UseJSON() bool {
	return p.useJSON
}

// Register registers key formatting flags with the given flag set.
func (p *CommonKeyListingParameters) Register(flags *flag.FlagSet) {
	flags.BoolVar(&p.useJSON, "json", false, "use machine-readable JSON output")
}

// ListKeySubcommand is the "acra-keys list" subcommand.
type ListKeySubcommand struct {
	CommonKeyStoreParameters
	CommonKeyListingParameters
	FlagSet *flag.FlagSet
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
	p.FlagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": list available keys in the keystore\n", CmdListKeys)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...]\n", os.Args[0], CmdListKeys)
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(p.FlagSet)
	}
}

// Parse command-line parameters of the subcommand.
func (p *ListKeySubcommand) Parse(arguments []string) error {
	return cmd.ParseFlagsWithConfig(p.FlagSet, arguments, DefaultConfigPath, ServiceName)
}

// Execute this subcommand.
func (p *ListKeySubcommand) Execute() {
	keyStore, err := OpenKeyStoreForReading(p)
	if err != nil {
		log.WithError(err).Fatal("Failed to open keystore")
	}
	ListKeysCommand(p, keyStore)
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

const (
	purposeHeader = "Key purpose"
	extraIDHeader = "Client/Zone ID"
	idHeader      = "Key ID"
)
