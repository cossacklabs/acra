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

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/network"
	tokenCommon "github.com/cossacklabs/acra/pseudonymization/common"
)

// DisableSubcommand is the "acra-tokens disable" subcommand.
type DisableSubcommand struct {
	flagSet *flag.FlagSet
	storage CommonTokenStorageParameters
	limits  CommonDateParameters
}

// CmdTokenDisable is the name of "acra-tokens disable" subcommand.
const CmdTokenDisable = "disable"

// Name returns the same of this subcommand.
func (s *DisableSubcommand) Name() string {
	return CmdTokenDisable
}

// FlagSet returns flag set of this subcommand.
func (s *DisableSubcommand) FlagSet() *flag.FlagSet {
	return s.flagSet
}

// RegisterFlags registers command-line flags of this subcommand.
func (s *DisableSubcommand) RegisterFlags() {
	s.flagSet = flag.NewFlagSet(CmdTokenDisable, flag.ContinueOnError)
	s.storage.Register(s.flagSet)
	s.limits.Register(s.flagSet)
	network.RegisterTLSBaseArgs(s.flagSet)
	cmd.RegisterRedisTokenStoreParametersWithPrefix(s.flagSet, "", "")
	s.flagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": disable tokens, preventing their use\n", CmdTokenDisable)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...]\n", os.Args[0], CmdTokenDisable)
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(s.flagSet)
	}
}

// Parse command-line parameters of the subcommand.
func (s *DisableSubcommand) Parse(arguments []string) error {
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
func (s *DisableSubcommand) Execute() {
	tokens, err := s.storage.Open(s.flagSet)
	if err != nil {
		log.WithError(err).Fatal("Cannot open token storage")
	}
	visitedCount := 0
	disabledCount := 0
	err = tokens.VisitMetadata(func(dataLength int, metadata tokenCommon.TokenMetadata) (tokenCommon.TokenAction, error) {
		if !s.limits.AccessedWithinLimits(metadata.Accessed) {
			return tokenCommon.TokenContinue, nil
		}
		if !s.limits.CreatedWithinLimits(metadata.Created) {
			return tokenCommon.TokenContinue, nil
		}
		visitedCount++
		if !metadata.Disabled {
			disabledCount++
			return tokenCommon.TokenDisable, nil
		}
		return tokenCommon.TokenContinue, nil
	})
	if err != nil {
		log.WithError(err).Fatal("Failed to scan token storage")
	}
	log.Infof("Disabled %d tokens (out of %d inspected)", disabledCount, visitedCount)
}
