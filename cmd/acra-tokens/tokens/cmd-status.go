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

// StatusSubcommand is the "acra-tokens status" subcommand.
type StatusSubcommand struct {
	flagSet *flag.FlagSet
	storage CommonTokenStorageParameters
	limits  CommonDateParameters
}

// CmdTokenStatus is the name of "acra-tokens status" subcommand.
const CmdTokenStatus = "status"

// Name returns the same of this subcommand.
func (s *StatusSubcommand) Name() string {
	return CmdTokenStatus
}

// FlagSet returns flag set of this subcommand.
func (s *StatusSubcommand) FlagSet() *flag.FlagSet {
	return s.flagSet
}

// RegisterFlags registers command-line flags of this subcommand.
func (s *StatusSubcommand) RegisterFlags() {
	s.flagSet = flag.NewFlagSet(CmdTokenStatus, flag.ContinueOnError)
	s.storage.Register(s.flagSet)
	s.limits.Register(s.flagSet)
	cmd.RegisterRedisTokenStoreParametersWithPrefix(s.flagSet, "", "")
	s.flagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": output token storage statistics\n", CmdTokenStatus)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...]\n", os.Args[0], CmdTokenStatus)
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(s.flagSet)
	}
}

// Parse command-line parameters of the subcommand.
func (s *StatusSubcommand) Parse(arguments []string) error {
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
func (s *StatusSubcommand) Execute() {
	tokens, err := s.storage.Open(s.flagSet)
	if err != nil {
		log.WithError(err).Fatal("Cannot open token storage")
	}
	totalTokenCount := 0
	totalStorageSize := 0
	disabledTokenCount := 0
	disabledStorageSize := 0
	err = tokens.VisitMetadata(func(dataLength int, metadata tokenCommon.TokenMetadata) (tokenCommon.TokenAction, error) {
		if !s.limits.AccessedWithinLimits(metadata.Accessed) {
			return tokenCommon.TokenContinue, nil
		}
		if !s.limits.CreatedWithinLimits(metadata.Created) {
			return tokenCommon.TokenContinue, nil
		}
		totalTokenCount++
		totalStorageSize += dataLength
		if metadata.Disabled {
			disabledTokenCount++
			disabledStorageSize += dataLength
		}
		return tokenCommon.TokenContinue, nil
	})
	if err != nil {
		log.WithError(err).Fatal("Failed to scan token storage")
	}
	fmt.Printf("TokenCount: %d\n", totalTokenCount)
	fmt.Printf("StorageSize: %d (%s)\n", totalStorageSize, humanReadableSize(totalStorageSize))
	fmt.Printf("DisabledTokenCount: %d\n", disabledTokenCount)
	fmt.Printf("DisabledStorageSize: %d (%s)\n", disabledStorageSize, humanReadableSize(disabledStorageSize))
}

func humanReadableSize(bytes int) string {
	if bytes <= 1024/2 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes <= (1024 * 1024 / 2) {
		return fmt.Sprintf("%0.2f KB", float32(bytes)/float32(1024))
	}
	if bytes <= (1024 * 1024 * 1024 / 2) {
		return fmt.Sprintf("%0.2f MB", float32(bytes)/float32(1024*1024))
	}
	return fmt.Sprintf("%0.2f GB", float32(bytes)/float32(1024*1024*1024))
}
