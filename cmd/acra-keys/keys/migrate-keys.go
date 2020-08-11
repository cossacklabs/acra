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

	"github.com/cossacklabs/acra/cmd"
	log "github.com/sirupsen/logrus"
)

// MigrateKeysParams ara parameters of "acra-keys migrate" subcommand.
type MigrateKeysParams interface {
	SrcKeyStoreVersion() string
	SrcKeyStoreParams() KeyStoreParameters
	DstKeyStoreVersion() string
	DstKeyStoreParams() KeyStoreParameters
	DryRun() bool
	ForceWrite() bool
}

// MigrateKeysSubcommand is the "acra-keys migrate" subcommand.
type MigrateKeysSubcommand struct {
	flagSet    *flag.FlagSet
	src, dst   CommonKeyStoreParameters
	srcVersion string
	dstVersion string
	dryRun     bool
	force      bool
}

// Command-line errors for "acra-keys migrate":
var (
	ErrMissingFormat = errors.New("key store format not specified")
	ErrMissingKeyDir = errors.New("key directory not specified")
)

// SrcKeyStoreVersion returns source key store version.
func (m *MigrateKeysSubcommand) SrcKeyStoreVersion() string {
	return m.srcVersion
}

// SrcKeyStoreParams returns parameters of the source key store.
func (m *MigrateKeysSubcommand) SrcKeyStoreParams() KeyStoreParameters {
	return &m.src
}

// DstKeyStoreVersion returns destination key store version.
func (m *MigrateKeysSubcommand) DstKeyStoreVersion() string {
	return m.dstVersion
}

// DstKeyStoreParams returns parameters of the destination key store.
func (m *MigrateKeysSubcommand) DstKeyStoreParams() KeyStoreParameters {
	return &m.dst
}

// DryRun returns true if only a dry run requested, without actual migration.
func (m *MigrateKeysSubcommand) DryRun() bool {
	return m.dryRun
}

// ForceWrite returns true if migration is allowed to overwrite existing destination key store.
func (m *MigrateKeysSubcommand) ForceWrite() bool {
	return m.force
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
	m.src.RegisterPrefixed(m.flagSet, "", "src_", "(old key store, source)")
	m.dst.RegisterPrefixed(m.flagSet, "", "dst_", "(new key store, destination)")
	m.flagSet.StringVar(&m.srcVersion, "src_keystore", "", "key store format to use: v1 (current), v2 (new)")
	m.flagSet.StringVar(&m.dstVersion, "dst_keystore", "", "key store format to use: v1 (current), v2 (new)")
	m.flagSet.BoolVar(&m.dryRun, "dry_run", false, "try migration without writing to the output key store")
	m.flagSet.BoolVar(&m.force, "force", false, "write to output key store even if it exists")
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
	err := cmd.ParseFlagsWithConfig(m.flagSet, arguments, DefaultConfigPath, ServiceName)
	if err != nil {
		return err
	}

	if m.srcVersion == "" {
		log.Warning("Missing required argument: --src_keystore={v1|v2}")
	}
	if m.dstVersion == "" {
		log.Warning("Missing required argument: --dst_keystore={v1|v2}")
	}
	if m.srcVersion == "" || m.dstVersion == "" {
		return ErrMissingFormat
	}

	if m.src.keyDir == "" {
		log.Warning("Missing required argument: --src_keys_dir=<path>")
	}
	if m.dst.keyDir == "" {
		log.Warning("Missing required argument: --dst_keys_dir=<path>")
	}
	if m.src.keyDir == "" || m.dst.keyDir == "" {
		return ErrMissingKeyDir
	}

	if m.src.keyDirPublic == "" {
		m.src.keyDirPublic = m.src.keyDir
	}
	if m.dst.keyDirPublic == "" {
		m.dst.keyDirPublic = m.dst.keyDir
	}

	return nil
}

// Execute this subcommand.
func (m *MigrateKeysSubcommand) Execute() {
}
