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
	"flag"
	"strings"

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

// CommandLineParams describes all command-line options of acra-keys.
type CommandLineParams struct {
	KeyStoreVersion string
	KeyDir          string
	KeyDirPublic    string

	ClientID string
	ZoneID   string

	ReadKeyKind    string
	DestroyKeyKind string
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
	flag.StringVar(&params.ReadKeyKind, "read_key", "", "key kind to read, one of: "+strings.Join(SupportedReadKeyKinds, ", "))
	flag.StringVar(&params.DestroyKeyKind, "destroy_key", "", "key kind to destroy, one of: "+strings.Join(SupportedDestroyKeyKinds, ", "))
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

	err := cmd.Parse(DefaultConfigPath, ServiceName)
	if err != nil {
		log.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Fatal("Cannot parse arguments")
	}

	Params.SetDefaults()
	Params.Check()
}
