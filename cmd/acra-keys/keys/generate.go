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

// GenerateKeyParams are parameters of "acra-keys generate" subcommand.
type GenerateKeyParams interface {
}

// GenerateKeySubcommand is the "acra-keys generate" subcommand.
type GenerateKeySubcommand struct {
	flagSet *flag.FlagSet
}

// Name returns the same of this subcommand.
func (g *GenerateKeySubcommand) Name() string {
	return CmdGenerate
}

// GetFlagSet returns flag set of this subcommand.
func (g *GenerateKeySubcommand) GetFlagSet() *flag.FlagSet {
	return g.flagSet
}

// RegisterFlags registers command-line flags of "acra-keys generate".
func (g *GenerateKeySubcommand) RegisterFlags() {
	g.flagSet = flag.NewFlagSet(CmdGenerate, flag.ContinueOnError)
	g.flagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": generate new keys\n", CmdGenerate)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...]\n", os.Args[0], CmdGenerate)
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(g.flagSet)
	}
}

// Parse command-line parameters of the subcommand.
func (g *GenerateKeySubcommand) Parse(arguments []string) error {
	err := cmd.ParseFlagsWithConfig(g.flagSet, arguments, DefaultConfigPath, ServiceName)
	if err != nil {
		return err
	}
	return nil
}

// Execute this subcommand.
func (g *GenerateKeySubcommand) Execute() {
}
