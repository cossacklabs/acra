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
	log "github.com/sirupsen/logrus"
)

// GenerateKeyParams are parameters of "acra-keys generate" subcommand.
type GenerateKeyParams interface {
	KeyStoreParameters
	KeyStoreVersion() string

	GenerateMasterKeyFile() string

	ClientID() []byte
	GenerateAcraConnector() bool
	GenerateAcraServer() bool
	GenerateAcraTranslator() bool
	GenerateAcraWriter() bool
	GenerateAcraWebConfig() bool
}

// GenerateKeySubcommand is the "acra-keys generate" subcommand.
type GenerateKeySubcommand struct {
	flagSet *flag.FlagSet

	CommonKeyStoreParameters
	keyStoreVersion string

	outKeyDir       string
	outKeyDirPublic string
	clientID        string
	masterKeyFile   string
	acraConnector   bool
	acraServer      bool
	acraTranslator  bool
	acraWriter      bool
	acraWebConfig   bool
}

// KeyStoreVersion returns requested key store version.
func (g *GenerateKeySubcommand) KeyStoreVersion() string {
	return g.keyStoreVersion
}

// ClientID returns client ID.
func (g *GenerateKeySubcommand) ClientID() []byte {
	return []byte(g.clientID)
}

// GenerateMasterKeyFile returns path to output file for master key.
// Returns empty string if master key has not been requested.
func (g *GenerateKeySubcommand) GenerateMasterKeyFile() string {
	return g.masterKeyFile
}

// GenerateAcraConnector returns true if new AcraConnector key was requested.
func (g *GenerateKeySubcommand) GenerateAcraConnector() bool {
	return g.acraConnector
}

// GenerateAcraServer returns true if new AcraServer key was requested.
func (g *GenerateKeySubcommand) GenerateAcraServer() bool {
	return g.acraServer
}

// GenerateAcraTranslator returns true if new AcraTranslator key was requested.
func (g *GenerateKeySubcommand) GenerateAcraTranslator() bool {
	return g.acraTranslator
}

// GenerateAcraWriter returns true if new AcraWriter key was requested.
func (g *GenerateKeySubcommand) GenerateAcraWriter() bool {
	return g.acraWriter
}

// GenerateAcraWebConfig returns true if new AcraWebConfig key was requested.
func (g *GenerateKeySubcommand) GenerateAcraWebConfig() bool {
	return g.acraWebConfig
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
	g.CommonKeyStoreParameters.Register(g.flagSet)
	g.flagSet.StringVar(&g.keyStoreVersion, "keystore", "", "Key store format: v1 (current), v2 (new)")
	g.flagSet.StringVar(&g.clientID, "client_id", "", "Client ID")
	g.flagSet.StringVar(&g.masterKeyFile, "master_key_path", "", "Generate new random master key and save to file")
	g.flagSet.BoolVar(&g.acraConnector, "acraconnector_transport_key", false, "Generate transport keypair for AcraConnector")
	g.flagSet.BoolVar(&g.acraServer, "acraserver_transport_key", false, "Generate transport keypair for AcraServer")
	g.flagSet.BoolVar(&g.acraTranslator, "acratranslator_transport_key", false, "Generate transport keypair for AcraTranslator")
	g.flagSet.BoolVar(&g.acraWriter, "client_storage_key", false, "Generate keypair for data encryption/decryption (for a client)")
	g.flagSet.BoolVar(&g.acraWebConfig, "acrawebconfig_symmetric_key", false, "Generate symmetric key for AcraWebconfig's basic auth DB")
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
	err = ValidateClientID(g)
	if err != nil {
		return err
	}
	return nil
}

// ValidateClientID checks that client ID is specified correctly.
func ValidateClientID(params GenerateKeyParams) error {
	clientID := params.ClientID()
	// If the client ID is specified then it must be a valid one.
	if len(clientID) != 0 {
		cmd.ValidateClientID(string(clientID))
	} else {
		// Client ID is required to generate some of the keys.
		// (Which are always generated on first launch, when --keystore is specified.)
		firstGeneration := params.KeyStoreVersion() != ""
		requestedClientKeys := params.GenerateAcraConnector() || params.GenerateAcraServer() || params.GenerateAcraTranslator() || params.GenerateAcraWriter()
		if firstGeneration || requestedClientKeys {
			log.Error("--client_id is required to generate keys")
			return ErrMissingClientID
		}
	}
	return nil
}

// Execute this subcommand.
func (g *GenerateKeySubcommand) Execute() {
}
