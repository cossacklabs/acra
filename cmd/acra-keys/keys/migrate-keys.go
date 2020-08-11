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
	"flag"
	"fmt"
	"os"

	"github.com/cossacklabs/acra/cmd"
)

// MigrateKeysParams ara parameters of "acra-keys migrate" subcommand.
type MigrateKeysParams interface {
}

// MigrateKeysSubcommand is the "acra-keys migrate" subcommand.
type MigrateKeysSubcommand struct {
	flagSet *flag.FlagSet
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
	m.flagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": migrate key store to a different format\n", CmdMigrateKeys)
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
	return cmd.ParseFlagsWithConfig(m.flagSet, arguments, DefaultConfigPath, ServiceName)
}

// Execute this subcommand.
func (m *MigrateKeysSubcommand) Execute() {
}
