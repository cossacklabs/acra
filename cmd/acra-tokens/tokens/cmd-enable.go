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

package tokens

import (
	"flag"
	"fmt"
	"os"

	"github.com/cossacklabs/acra/cmd"
	tokenCommon "github.com/cossacklabs/acra/pseudonymization/common"
	log "github.com/sirupsen/logrus"
)

// EnableSubcommand is the "acra-tokens enable" subcommand.
type EnableSubcommand struct {
	flagSet *flag.FlagSet
	storage CommonTokenStorageParameters
	limits  CommonDateParameters
}

// CmdTokenEnable is the name of "acra-tokens enable" subcommand.
const CmdTokenEnable = "enable"

// Name returns the same of this subcommand.
func (s *EnableSubcommand) Name() string {
	return CmdTokenEnable
}

// FlagSet returns flag set of this subcommand.
func (s *EnableSubcommand) FlagSet() *flag.FlagSet {
	return s.flagSet
}

// RegisterFlags registers command-line flags of this subcommand.
func (s *EnableSubcommand) RegisterFlags() {
	s.flagSet = flag.NewFlagSet(CmdTokenEnable, flag.ContinueOnError)
	s.storage.Register(s.flagSet)
	s.limits.Register(s.flagSet)
	cmd.RegisterRedisKeystoreParametersWithPrefix(s.flagSet, "", "")
	s.flagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": enable back once disabled tokens, allowing their use\n", CmdTokenEnable)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...]\n", os.Args[0], CmdTokenEnable)
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(s.flagSet)
	}
}

// Parse command-line parameters of the subcommand.
func (s *EnableSubcommand) Parse(arguments []string) error {
	err := cmd.ParseFlagsWithConfig(s.flagSet, arguments, DefaultConfigPath, ServiceName)
	if err != nil {
		return err
	}
	err = s.storage.Validate(s.flagSet)
	if err != nil {
		return err
	}
	err = s.limits.Validate()
	if err != nil {
		return err
	}
	return nil
}

// Execute this subcommand.
func (s *EnableSubcommand) Execute() {
	tokens, err := s.storage.Open(s.flagSet)
	if err != nil {
		log.WithError(err).Fatal("Cannot open token storage")
	}
	visitedCount := 0
	enabledCount := 0
	err = tokens.VisitMetadata(func(dataLength int, metadata tokenCommon.TokenMetadata) (tokenCommon.TokenAction, error) {
		if !s.limits.AccessedWithinLimits(metadata.Accessed) {
			return tokenCommon.TokenContinue, nil
		}
		if !s.limits.CreatedWithinLimits(metadata.Created) {
			return tokenCommon.TokenContinue, nil
		}
		visitedCount++
		if metadata.Disabled {
			enabledCount++
			return tokenCommon.TokenEnable, nil
		}
		return tokenCommon.TokenContinue, nil
	})
	if err != nil {
		log.WithError(err).Fatal("Failed to scan token storage")
	}
	log.Infof("Enabled %d tokens (out of %d inspected)", enabledCount, visitedCount)
}
