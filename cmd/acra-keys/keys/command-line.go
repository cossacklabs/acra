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

// Package keys defines reusable business logic of `acra-keys` utility.
package keys

import (
	"errors"
	"flag"

	"github.com/cossacklabs/acra/cmd"
	keystoreV1 "github.com/cossacklabs/acra/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
)

// ServiceName constant for logging and configuration parsing.
const ServiceName = "acra-keys"

// DefaultKeyDirectory is the default path to key directory.
const DefaultKeyDirectory = keystoreV1.DefaultKeyDirShort

// DefaultConfigPath is the default path to service configuration file.
var DefaultConfigPath = utils.GetConfigPathByName("acra-keys")

// Sub-command names:
const (
	CmdReadKey    = "read"
	CmdDestroyKey = "destroy"
)

// SupportedSubCommands lists supported sub-commands or CLI.
var SupportedSubCommands = []string{
	CmdReadKey,
	CmdDestroyKey,
}

// Key kind constants:
const (
	KeyPoisonPublic   = "poison-public"
	KeyPoisonPrivate  = "poison-private"
	KeyStoragePublic  = "storage-public"
	KeyStoragePrivate = "storage-private"
	KeyZonePublic     = "zone-public"
	KeyZonePrivate    = "zone-private"

	KeyTransportConnector  = "transport-connector"
	KeyTransportServer     = "transport-server"
	KeyTransportTranslator = "transport-translator"
)

// Comman-line parsing errors:
var (
	ErrUnknownSubCommand = errors.New("unknown command")
	ErrMissingKeyKind    = errors.New("missing key kind")
	ErrMultipleKeyKinds  = errors.New("multiple key kinds")
)

// CommandLineParams describes all command-line options of acra-keys.
type CommandLineParams struct {
	KeyStoreVersion string
	KeyDir          string
	KeyDirPublic    string

	ClientID string
	ZoneID   string

	Command string

	ReadKeyKind    string
	DestroyKeyKind string

	readFlags    *flag.FlagSet
	destroyFlags *flag.FlagSet
}

// Params provide global access to command-line parameters.
var Params *CommandLineParams = &CommandLineParams{}

// Register configures command-line parameter parsing.
func (params *CommandLineParams) Register() {
	flag.StringVar(&params.KeyStoreVersion, "keystore", "", "force key store format: v1 (current), v2 (new)")
	flag.StringVar(&params.KeyDir, "keys_dir", DefaultKeyDirectory, "path to key directory")
	flag.StringVar(&params.KeyDirPublic, "keys_dir_public", "", "path to key directory for public keys")
	flag.StringVar(&params.ClientID, "client_id", "", "client ID for which to retrieve key")
	flag.StringVar(&params.ZoneID, "zone_id", "", "zone ID for which to retrieve key")

	params.readFlags = flag.NewFlagSet(CmdReadKey, flag.ContinueOnError)
	params.readFlags.StringVar(&params.ClientID, "client_id", "", "client ID for which to retrieve key")
	params.readFlags.StringVar(&params.ZoneID, "zone_id", "", "zone ID for which to retrieve key")

	params.destroyFlags = flag.NewFlagSet(CmdDestroyKey, flag.ContinueOnError)
	params.destroyFlags.StringVar(&params.ClientID, "client_id", "", "client ID for which to destroy key")
	params.destroyFlags.StringVar(&params.ZoneID, "zone_id", "", "zone ID for which to destroy key")
}

// Parse parses complete command-line.
func (params *CommandLineParams) Parse() error {
	err := cmd.Parse(DefaultConfigPath, ServiceName)
	if err != nil {
		return err
	}
	err = params.ParseSubCommand()
	if err != nil {
		return err
	}
	return nil
}

// ParseSubCommand parses sub-command and its arguments.
func (params *CommandLineParams) ParseSubCommand() error {
	args := flag.Args()
	if len(args) == 0 {
		log.WithField("supported", SupportedSubCommands).
			Info("No command specified")
		return nil
	}
	params.Command = args[0]
	switch args[0] {
	case CmdReadKey:
		err := params.readFlags.Parse(args[1:])
		if err != nil {
			return err
		}
		args := params.readFlags.Args()
		if len(args) < 1 {
			log.Errorf("\"%s\" command requires key kind", CmdReadKey)
			return ErrMissingKeyKind
		}
		// It makes sense to allow multiple keys, but we can't think of a useful
		// output format for that, so we currently don't allow it.
		if len(args) > 1 {
			log.Errorf("\"%s\" command does not support more than one key kind", CmdReadKey)
			return ErrMultipleKeyKinds
		}
		params.ReadKeyKind = args[0]
		return nil

	case CmdDestroyKey:
		err := params.destroyFlags.Parse(args[1:])
		if err != nil {
			return err
		}
		args := params.destroyFlags.Args()
		if len(args) < 1 {
			log.Errorf("\"%s\" command requires key kind", CmdDestroyKey)
			return ErrMissingKeyKind
		}
		// It makes sense to allow multiple keys, but we can't think of a useful
		// output format for that, so we currently don't allow it.
		if len(args) > 1 {
			log.Errorf("\"%s\" command does not support more than one key kind", CmdDestroyKey)
			return ErrMultipleKeyKinds
		}
		params.DestroyKeyKind = args[0]
		return nil

	default:
		log.WithField("expected", SupportedSubCommands).
			Errorf("Unknown command: %s", args[0])
		return ErrUnknownSubCommand
	}
}

// SetDefaults sets dynamically configured default values of command-line parameters.
func (params *CommandLineParams) SetDefaults() {
	if params.KeyStoreVersion == "" {
		if filesystemV2.IsKeyDirectory(params.KeyDir) {
			params.KeyStoreVersion = "v2"
		} else {
			params.KeyStoreVersion = "v1"
		}
	}

	if params.KeyDirPublic == "" {
		params.KeyDirPublic = params.KeyDir
	}
}

// Check command-line for consistency. Exit the process on error.
func (params *CommandLineParams) Check() {
	if params.ClientID != "" && params.ZoneID != "" {
		log.Fatal("--client_id and --zone_id cannot be used simultaneously")
	}

	if params.ReadKeyKind != "" && params.DestroyKeyKind != "" {
		log.Fatal("--read_key and --destroy_key cannot be used simultaneously")
	}
}

// ParseParams will parse complete command-line and fill in `Params` values.
// It will exit on any issues with the configuration.
func ParseParams() {
	Params.Register()

	err := Params.Parse()
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Fatal("Cannot parse arguments")
	}

	Params.SetDefaults()
	Params.Check()
}
