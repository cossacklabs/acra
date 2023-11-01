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
	"errors"
	"flag"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/cmd/args"
	"github.com/cossacklabs/acra/network"
	tokenCommon "github.com/cossacklabs/acra/pseudonymization/common"
)

// RemoveSubcommand is the "acra-tokens remove" subcommand.
type RemoveSubcommand struct {
	flagSet   *flag.FlagSet
	extractor *args.ServiceExtractor
	storage   CommonTokenStorageParameters
	limits    CommonDateParameters

	dryRun         bool
	removeAll      bool
	removeDisabled bool
}

// CmdTokenRemove is the name of "acra-tokens remove" subcommand.
const CmdTokenRemove = "remove"

// Errors returned by "acra-tokens remove" subcommand.
var (
	ErrRemoveNotSpecified = errors.New("underspecified removal conditions")
)

// Name returns the same of this subcommand.
func (s *RemoveSubcommand) Name() string {
	return CmdTokenRemove
}

// FlagSet returns flag set of this subcommand.
func (s *RemoveSubcommand) FlagSet() *flag.FlagSet {
	return s.flagSet
}

// RegisterFlags registers command-line flags of this subcommand.
func (s *RemoveSubcommand) RegisterFlags() {
	s.flagSet = flag.NewFlagSet(CmdTokenRemove, flag.ContinueOnError)
	s.storage.Register(s.flagSet)
	s.limits.Register(s.flagSet)
	network.RegisterTLSBaseArgs(s.flagSet)
	s.flagSet.BoolVar(&s.dryRun, "dry_run", false, "do not actually remove tokens, only output status")
	s.flagSet.BoolVar(&s.removeAll, "all", false, "remove all requested tokens within specified date range, regardless of their state (enabled and disabled)")
	s.flagSet.BoolVar(&s.removeAll, "only_disabled", false, "remove only disabled tokens within specified date range")
	cmd.RegisterRedisTokenStoreParametersWithPrefix(s.flagSet, "", "")
	s.flagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": remove tokens from the storage\n", CmdTokenRemove)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...]\n", os.Args[0], CmdTokenRemove)
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(s.flagSet)
	}
}

// Parse command-line parameters of the subcommand.
func (s *RemoveSubcommand) Parse(arguments []string) error {
	err := cmd.ParseFlags(s.flagSet, arguments)
	if err != nil {
		return err
	}
	serviceConfig, err := cmd.ParseConfig(DefaultConfigPath, ServiceName)
	if err != nil {
		return err
	}
	s.extractor = args.NewServiceExtractor(s.flagSet, serviceConfig)

	err = s.storage.Validate(s.extractor)
	if err != nil {
		return err
	}
	err = s.limits.Validate()
	if err != nil {
		return err
	}
	if !(s.removeAll || s.removeDisabled) {
		log.Warning("Either --all or --only_disabled must be specified")
		return ErrRemoveNotSpecified
	}
	return nil
}

// Execute this subcommand.
func (s *RemoveSubcommand) Execute() {
	tokens, err := s.storage.Open(s.extractor)
	if err != nil {
		log.WithError(err).Fatal("Cannot open token storage")
	}
	totalCount := 0
	removedCount := 0
	removedBytes := 0
	err = tokens.VisitMetadata(func(dataLength int, metadata tokenCommon.TokenMetadata) (tokenCommon.TokenAction, error) {
		totalCount++
		if !s.limits.AccessedWithinLimits(metadata.Accessed) {
			return tokenCommon.TokenContinue, nil
		}
		if !s.limits.CreatedWithinLimits(metadata.Created) {
			return tokenCommon.TokenContinue, nil
		}
		if s.removeAll || (s.removeDisabled && metadata.Disabled) {
			removedCount++
			removedBytes += dataLength
			// If this is a dry run, compute all the stats, but don't issue remove command.
			if s.dryRun {
				return tokenCommon.TokenContinue, nil
			}
			return tokenCommon.TokenRemove, nil
		}
		return tokenCommon.TokenContinue, nil
	})
	if err != nil {
		log.WithError(err).Fatal("Failed to scan token storage")
	}
	log.Infof("Removed %d tokens (out of %d in total)", removedCount, totalCount)
	log.Infof("Freed approximately %s of token storage", humanReadableSize(removedBytes))
	if s.dryRun {
		log.Infof("Now run without --dry_run to actually remove the tokens")
	}
}
