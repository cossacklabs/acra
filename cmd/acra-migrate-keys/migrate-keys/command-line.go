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

// Package migratekeys implements common procedures for "acra-migrate-keys" tool.
package migratekeys

import (
	"errors"
	"flag"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

// Command-line errors:
var (
	ErrMissingFormat = errors.New("key store format not specified")
	ErrMissingKeyDir = errors.New("key directory not specified")
)

var (
	defaultConfigPath = utils.GetConfigPathByName("acra-migrate-keys")
	serviceName       = "acra-migrate-keys"
)

// CommandLineParams - command-line options.
type CommandLineParams struct {
	Src, Dst KeyStoreParams
	Misc     MiscParams
}

// KeyStoreParams - key store parameters.
type KeyStoreParams struct {
	KeyStoreVersion string
	KeyDir          string
	KeyDirPublic    string
}

// MiscParams - miscellaneous parameters.
type MiscParams struct {
	DryRun bool
	Force  bool

	LogDebug   bool
	LogVerbose bool
}

// OpenMode - whether key store is source or destination.
type OpenMode int

// OpenMode constant values:
const (
	OpenSrc OpenMode = iota
	OpenDst
)

// Params stores command-line parameters of "acra-migrate-keys" tool.
var Params CommandLineParams

// RegisterCommandLineParams registers command-line options for parsing.
func RegisterCommandLineParams() *CommandLineParams {
	// Source key store
	flag.StringVar(&Params.Src.KeyStoreVersion, "src_keystore", "", "key store format to use: v1 (current), v2 (new)")
	flag.StringVar(&Params.Src.KeyDir, "src_keys_dir", "", "path to source key directory")
	flag.StringVar(&Params.Src.KeyDirPublic, "src_keys_dir_public", "", "path to source key directory for public keys")
	// Destination key store
	flag.StringVar(&Params.Dst.KeyStoreVersion, "dst_keystore", "", "key store format to use: v1 (current), v2 (new)")
	flag.StringVar(&Params.Dst.KeyDir, "dst_keys_dir", "", "path to destination key directory")
	flag.StringVar(&Params.Dst.KeyDirPublic, "dst_keys_dir_public", "", "path to destination key directory for public keys")
	// Miscellaneous
	flag.BoolVar(&Params.Misc.DryRun, "dry_run", false, "try migration without writing to the output key store")
	flag.BoolVar(&Params.Misc.Force, "force", false, "write to output key store even if it exists")
	flag.BoolVar(&Params.Misc.LogDebug, "d", false, "log debug messages to stderr")
	flag.BoolVar(&Params.Misc.LogVerbose, "v", false, "log more information to stderr")

	return &Params
}

// Parse parses command-line, validates commad-line options, and initializes default paramater values.
func (params *CommandLineParams) Parse() error {
	err := cmd.Parse(defaultConfigPath, serviceName)
	if err != nil {
		return err
	}

	if params.Src.KeyStoreVersion == "" {
		log.Warning("Missing required argument: --src_keystore={v1|v2}")
	}
	if params.Dst.KeyStoreVersion == "" {
		log.Warning("Missing required argument: --dst_keystore={v1|v2}")
	}
	if params.Src.KeyStoreVersion == "" || params.Dst.KeyStoreVersion == "" {
		return ErrMissingFormat
	}

	if params.Src.KeyDir == "" {
		log.Warning("Missing required argument: --src_keys_dir=<path>")
	}
	if params.Dst.KeyDir == "" {
		log.Warning("Missing required argument: --dst_keys_dir=<path>")
	}
	if params.Src.KeyDir == "" || params.Dst.KeyDir == "" {
		return ErrMissingKeyDir
	}

	if params.Src.KeyDirPublic == "" {
		params.Src.KeyDirPublic = params.Src.KeyDir
	}
	if params.Dst.KeyDirPublic == "" {
		params.Dst.KeyDirPublic = params.Dst.KeyDir
	}

	if params.Misc.LogDebug {
		log.SetLevel(log.TraceLevel)
	}
	if params.Misc.LogVerbose {
		log.SetLevel(log.DebugLevel)
	}

	return nil
}
