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
	"io/ioutil"
	"os"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
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

	ZoneID() []byte
	GenerateNewZone() bool
	GenerateZoneKeys() bool
}

// Key generation errors:
var (
	ErrMissingKeyStoreVersion = errors.New("key store version not specified")
	ErrUnknownKeyStoreVersion = errors.New("unknown key store version")
)

// GenerateKeySubcommand is the "acra-keys generate" subcommand.
type GenerateKeySubcommand struct {
	flagSet *flag.FlagSet

	CommonKeyStoreParameters
	keyStoreVersion string

	outKeyDir       string
	outKeyDirPublic string
	clientID        string
	zoneID          string
	masterKeyFile   string
	acraConnector   bool
	acraServer      bool
	acraTranslator  bool
	acraWriter      bool
	acraWebConfig   bool
	newZone         bool
	rotateZone      bool
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

// ZoneID returns zone ID.
func (g *GenerateKeySubcommand) ZoneID() []byte {
	return []byte(g.zoneID)
}

// GenerateNewZone returns true if a new zone was requested.
func (g *GenerateKeySubcommand) GenerateNewZone() bool {
	return g.newZone
}

// GenerateZoneKeys returns true if a new key for a zone was requested.
func (g *GenerateKeySubcommand) GenerateZoneKeys() bool {
	return g.rotateZone
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
	g.flagSet.StringVar(&g.zoneID, "zone_id", "", "Zone ID")
	g.flagSet.StringVar(&g.masterKeyFile, "master_key_path", "", "Generate new random master key and save to file")
	g.flagSet.BoolVar(&g.acraConnector, "acraconnector_transport_key", false, "Generate transport keypair for AcraConnector")
	g.flagSet.BoolVar(&g.acraServer, "acraserver_transport_key", false, "Generate transport keypair for AcraServer")
	g.flagSet.BoolVar(&g.acraTranslator, "acratranslator_transport_key", false, "Generate transport keypair for AcraTranslator")
	g.flagSet.BoolVar(&g.acraWriter, "client_storage_key", false, "Generate keypair for data encryption/decryption (for a client)")
	g.flagSet.BoolVar(&g.acraWebConfig, "acrawebconfig_symmetric_key", false, "Generate symmetric key for AcraWebconfig's basic auth DB")
	g.flagSet.BoolVar(&g.newZone, "new_zone", false, "Generate new Acra storage zone")
	g.flagSet.BoolVar(&g.rotateZone, "zone_storage_key", false, "Rotate existing Acra zone storagae keypair")
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
	err = ValidateZoneID(g)
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
		// Unless we're only generating the master key.
		masterKey := params.GenerateMasterKeyFile() != ""
		firstGeneration := params.KeyStoreVersion() != ""
		requestedClientKeys := params.GenerateAcraConnector() || params.GenerateAcraServer() || params.GenerateAcraTranslator() || params.GenerateAcraWriter()
		if !masterKey && (firstGeneration || requestedClientKeys) {
			log.Error("--client_id is required to generate keys")
			return ErrMissingClientID
		}
	}
	return nil
}

// ValidateZoneID checks that zone ID is specified correctly.
func ValidateZoneID(params GenerateKeyParams) error {
	zoneID := params.ZoneID()
	// Zone ID is required to generate some of the keys.
	if len(zoneID) == 0 {
		if params.GenerateZoneKeys() {
			log.Error("--zone_id is required to generate zone keys")
			return ErrMissingZoneID
		}
	}
	return nil
}

// Execute this subcommand.
func (g *GenerateKeySubcommand) Execute() {
	if g.GenerateMasterKeyFile() != "" {
		err := GenerateMasterKey(g)
		if err != nil {
			log.WithError(err).Fatal("Failed to generate master key")
		}
		return
	}

	// If the keystore already exists, detect its version automatically.
	// Otherwise require the user to specify it. (Only during key generation.)
	var keystore keystore.KeyMaking
	var err error
	keystoreVersion := g.KeyStoreVersion()
	if keystoreVersion == "" {
		if filesystemV2.IsKeyDirectory(g.KeyDir()) {
			keystoreVersion = "v2"
		} else if filesystem.IsKeyDirectory(g.KeyDir()) {
			keystoreVersion = "v1"
		}
	}
	switch keystoreVersion {
	case "v1":
		keystore, err = openKeyStoreV1(g)
	case "v2":
		keystore, err = openKeyStoreV2(g)
	case "":
		log.Fatalf("Keystore version is required: --keystore={v1|v2}")
	default:
		log.Fatalf("Unknown --keystore option: %v", keystoreVersion)
	}
	if err != nil {
		log.WithError(err).Fatal("Failed to open keystore")
	}

	generatedKeys, err := GenerateAcraKeys(g, keystore)
	if err != nil {
		log.WithError(err).Fatal("Failed to generate keys")
	}
	if !generatedKeys {
		log.Info("No keys were updated")
	}
}

// GenerateMasterKey generates master key into output file.
func GenerateMasterKey(params GenerateKeyParams) error {
	var newKey []byte
	var err error

	version := params.KeyStoreVersion()
	switch version {
	case "v1":
		newKey, err = keystore.GenerateSymmetricKey()
	case "v2":
		newKey, err = keystoreV2.NewSerializedMasterKeys()
	case "":
		log.Errorf("Key store version is required: --keystore={v1|v2}")
		return ErrMissingKeyStoreVersion
	default:
		log.Errorf("Unknown --keystore option: %v", version)
		return ErrUnknownKeyStoreVersion
	}
	if err != nil {
		return err
	}

	masterKeyFile := params.GenerateMasterKeyFile()
	if err := ioutil.WriteFile(masterKeyFile, newKey, 0600); err != nil {
		log.WithError(err).WithField("path", masterKeyFile).Error("Failed to write master key")
		return err
	}

	return nil
}

// GenerateAcraKeys generates Acra CE keys as specified by the parameters.
// Returns true if some keys have been generated.
func GenerateAcraKeys(params GenerateKeyParams, keystore keystore.KeyMaking) (bool, error) {
	generateAcraConnector := params.GenerateAcraConnector()
	generateAcraServer := params.GenerateAcraServer()
	generateAcraTranslator := params.GenerateAcraTranslator()
	generateAcraWriter := params.GenerateAcraWriter()

	// If this is keystore initialization, allow the user to avoid specifying keys.
	// They will need all of them so just generate the default set.
	// However, if the keystore is already present then rotate only the specified keys.
	firstGeneration := params.KeyStoreVersion() != ""
	explictKeys := generateAcraConnector || generateAcraServer || generateAcraTranslator || generateAcraWriter
	clientIDKnown := len(params.ClientID()) != 0
	if firstGeneration && !explictKeys && clientIDKnown {
		generateAcraConnector = true
		generateAcraServer = true
		generateAcraTranslator = true
		generateAcraWriter = true
	}

	// If the user runs just "acra-keys generate" with no arguments and the configuration file
	// does not tell us the action either, we end up not doing anything useful.
	// Return this state to the caller so that we can at least tell the user than nothing changed
	// instead of keeping an ominous silence.
	didSomething := false

	if generateAcraConnector {
		err := keystore.GenerateConnectorKeys(params.ClientID())
		if err != nil {
			log.WithError(err).Error("Failed to generate AcraConnector transport key")
			return didSomething, err
		}
		log.Info("Generated AcraConnector transport key")
		didSomething = true
	}
	if generateAcraServer {
		err := keystore.GenerateServerKeys(params.ClientID())
		if err != nil {
			log.WithError(err).Error("Failed to generate AcraServer transport key")
			return didSomething, err
		}
		log.Info("Generated AcraServer transport key")
		didSomething = true
	}
	if generateAcraTranslator {
		err := keystore.GenerateTranslatorKeys(params.ClientID())
		if err != nil {
			log.WithError(err).Error("Failed to generate AcraTranslator transport key")
			return didSomething, err
		}
		log.Info("Generated AcraTranslator transport key")
		didSomething = true
	}
	if generateAcraWriter {
		err := keystore.GenerateDataEncryptionKeys(params.ClientID())
		if err != nil {
			log.WithError(err).Error("Failed to generate client storage key")
			return didSomething, err
		}
		log.Info("Generated client storage key")
		didSomething = true
	}

	if params.GenerateAcraWebConfig() {
		// Create the key if it does not exits.
		_, err := keystore.GetAuthKey(true)
		if err != nil {
			log.WithError(err).Error("Failed to generate AcraWebConfig key")
			return didSomething, err
		}
		log.Info("Generated AcraWebConfig symmetric key")
		didSomething = true
	}

	if params.GenerateNewZone() {
		id, publicKey, err := keystore.GenerateZoneKey()
		if err != nil {
			log.WithError(err).Error("Failed to generate new zone")
			return didSomething, err
		}
		json, err := zone.ZoneDataToJSON(id, &keys.PublicKey{Value: publicKey})
		if err != nil {
			log.WithError(err).Error("Failed to serialize new zone parameters")
			return didSomething, err
		}
		fmt.Println(string(json))
		log.Info("Generated new Acra zone")
		didSomething = true
	}
	if params.GenerateZoneKeys() {
		zoneID := params.ZoneID()
		publicKey, err := keystore.RotateZoneKey(zoneID)
		if err != nil {
			log.WithError(err).Error("Failed to rotate zone key")
			return didSomething, err
		}
		json, err := zone.ZoneDataToJSON(zoneID, &keys.PublicKey{Value: publicKey})
		if err != nil {
			log.WithError(err).Error("Failed to serialize zone parameters")
			return didSomething, err
		}
		fmt.Println(string(json))
		log.Info("Generated zone storage key")
		didSomething = true
	}

	return didSomething, nil
}
