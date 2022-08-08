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
	"github.com/cossacklabs/acra/keystore/keyloader"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
)

// GenerateKeyParams are parameters of "acra-keys generate" subcommand.
type GenerateKeyParams interface {
	KeyStoreParameters
	KeystoreVersion() string

	GenerateMasterKeyFile() string

	ClientID() []byte
	GenerateAcraWriter() bool
	GenerateAcraBlocks() bool
	GenerateSearchHMAC() bool
	GeneratePoisonRecord() bool
	GenerateAuditLog() bool
	SetClientID(clientID string)
	TLSClientCert() string
	TLSIdentifierExtractorType() string

	ZoneID() []byte
	GenerateNewZone() bool
	GenerateZoneKeys() bool
	GenerateZoneSymmetricKey() bool

	SpecificKeysRequested() bool
}

// Key generation errors:
var (
	ErrMissingKeystoreVersion = errors.New("keystore version not specified")
	ErrUnknownKeystoreVersion = errors.New("unknown keystore version")
)

// GenerateKeySubcommand is the "acra-keys generate" subcommand.
type GenerateKeySubcommand struct {
	flagSet *flag.FlagSet

	CommonExtractClientIDParameters
	CommonKeyStoreParameters

	keystoreVersion string

	outKeyDir       string
	outKeyDirPublic string
	clientID        string
	zoneID          string
	masterKeyFile   string
	acraWriter      bool
	newZone         bool
	rotateZone      bool
	rotateZoneSym   bool
	acraBlocks      bool
	auditLog        bool
	searchHMAC      bool
	poisonRecord    bool
}

// GenerateAuditLog get auditLog flag
func (g *GenerateKeySubcommand) GenerateAuditLog() bool {
	return g.auditLog
}

// GeneratePoisonRecord get poisonRecord flag
func (g *GenerateKeySubcommand) GeneratePoisonRecord() bool {
	return g.poisonRecord
}

// KeystoreVersion returns requested keystore version.
func (g *GenerateKeySubcommand) KeystoreVersion() string {
	return g.keystoreVersion
}

// SetClientID set specific client ID.
func (g *GenerateKeySubcommand) SetClientID(clientID string) {
	g.clientID = clientID
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

// GenerateAcraWriter returns true if new AcraWriter key was requested.
func (g *GenerateKeySubcommand) GenerateAcraWriter() bool {
	return g.acraWriter
}

// GenerateAcraBlocks get acraBlocks flag
func (g *GenerateKeySubcommand) GenerateAcraBlocks() bool {
	return g.acraBlocks
}

// GenerateSearchHMAC get searchHMAC flag
func (g *GenerateKeySubcommand) GenerateSearchHMAC() bool {
	return g.searchHMAC
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

// GenerateZoneSymmetricKey returns true if a new sym key for a zone was requested.
func (g *GenerateKeySubcommand) GenerateZoneSymmetricKey() bool {
	return g.rotateZoneSym
}

// SpecificKeysRequested returns true if the user has requested any key specifically.
// It returns false if no keys were requested.
func (g *GenerateKeySubcommand) SpecificKeysRequested() bool {
	return g.acraWriter || g.newZone ||
		g.rotateZone || g.acraBlocks || g.auditLog || g.searchHMAC || g.poisonRecord || g.rotateZoneSym
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
	g.CommonExtractClientIDParameters.Register(g.flagSet)
	g.flagSet.StringVar(&g.keystoreVersion, "keystore", "", "Keystore format: v1 (current), v2 (new)")
	g.flagSet.StringVar(&g.clientID, "client_id", "", "Client ID")
	g.flagSet.StringVar(&g.zoneID, "zone_id", "", "Zone ID")
	g.flagSet.BoolVar(&g.acraWriter, "client_storage_key", false, "Generate keypair for data encryption/decryption (for a client)")
	g.flagSet.BoolVar(&g.newZone, "zone", false, "Generate new Acra storage zone")
	g.flagSet.BoolVar(&g.rotateZone, "zone_storage_key", false, "Rotate existing Acra zone storage keypair")
	g.flagSet.BoolVar(&g.rotateZoneSym, "zone_symmetric_key", false, "Rotate existing Acra zone symmetric key")
	g.flagSet.BoolVar(&g.acraBlocks, "client_storage_symmetric_key", false, "Generate symmetric key for data encryption (using AcraBlocks)")
	g.flagSet.BoolVar(&g.auditLog, "audit_log_symmetric_key", false, "Generate symmetric key for log integrity checks")
	g.flagSet.BoolVar(&g.searchHMAC, "search_hmac_symmetric_key", false, "Generate symmetric key for searchable encryption HMAC")
	g.flagSet.BoolVar(&g.poisonRecord, "poison_record_keys", false, "Generate keypair and symmetric key for poison records")
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
	// If we are asked to get a master key we don't care for the client ID.
	if params.GenerateMasterKeyFile() != "" {
		return nil
	}

	clientID := params.ClientID()
	tlsClientCert := params.TLSClientCert()

	// If the client ID is specified then it must be a valid one.
	if len(clientID) != 0 {
		if tlsClientCert != "" {
			log.Errorln("You can either specify identifier for keys via specific clientID by --client_id parameter or via TLS certificate by --tls_cert parameter.")
			return ErrClientIDWithTLSCertProvided
		}

		cmd.ValidateClientID(string(clientID))
	} else {
		// Client ID is required to generate some of the keys.
		// (Which are always generated on first launch, when --keystore is specified.)
		// Unless we're only generating the master key.
		masterKey := params.GenerateMasterKeyFile() != ""
		firstGeneration := params.KeystoreVersion() != ""
		requestedClientKeys := params.GenerateAcraWriter() || params.GenerateAcraBlocks() || params.GenerateSearchHMAC()

		requestedNonClientKeys := params.GeneratePoisonRecord() || params.GenerateAuditLog()

		// skip clientID validation if only non-clientID based keys requested to generate
		if requestedNonClientKeys && !requestedClientKeys {
			return nil
		}

		if !masterKey && (firstGeneration || requestedClientKeys) {
			if tlsClientCert != "" {
				clientIDFromCert, err := ExtractClientID(params)
				if err != nil {
					log.WithError(err).Fatal("Failed to generate clientID from cert")
					return err
				}
				params.SetClientID(clientIDFromCert)
				return nil
			}

			log.Error("--client_id or --tls_cert is required to generate keys")
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
	var keyStore keystore.KeyMaking
	var err error
	keystoreVersion := g.KeystoreVersion()
	if keystoreVersion == "" {
		if IsKeyStoreV2(g) {
			keystoreVersion = "v2"
		} else if IsKeyStoreV1(g) {
			keystoreVersion = "v1"
		}
	}

	masterKeyLoaderFactory := keyloader.NewMasterKeyLoaderFactory(g.CommonKeyStoreParameters.KeyLoaderCLIOptions().KeystoreEncryptorType)
	keyLoader, err := keyloader.GetInitializedMasterKeyLoader(masterKeyLoaderFactory)
	if err != nil {
		return
	}

	switch keystoreVersion {
	case "v1":
		keyStore, err = openKeyStoreV1(g, keyLoader)
	case "v2":
		keyStore, err = openKeyStoreV2(g, keyLoader)
	case "":
		log.Fatalf("Keystore version is required: --keystore={v1|v2}")
	default:
		log.Fatalf("Unknown --keystore option: %v", keystoreVersion)
	}
	if err != nil {
		log.WithError(err).Fatal("Failed to open keystore")
	}

	generatedKeys, err := GenerateAcraKeys(g, keyStore, GenerateOnInitialize)
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

	version := params.KeystoreVersion()
	switch version {
	case "v1":
		newKey, err = keystore.GenerateSymmetricKey()
	case "v2":
		newKey, err = keystoreV2.NewSerializedMasterKeys()
	case "":
		log.Errorf("Keystore version is required: --keystore={v1|v2}")
		return ErrMissingKeystoreVersion
	default:
		log.Errorf("Unknown --keystore option: %v", version)
		return ErrUnknownKeystoreVersion
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

// DefaultKeyAction defines how GenerateAcraKeys() handles the default key set.
type DefaultKeyAction int

// Allowed values of DefaultKeyAction.
const (
	// Automatically generate default set of keys if no keys were requested and the keystore is empty.
	GenerateOnInitialize DefaultKeyAction = iota
	// Generate only the explicitly requested keys.
	GenerateAsRequested
	// Generate default set of keys regardless of the requested keys.
	GenerateDefaultsOverride
)

// GenerateAcraKeys generates Acra CE keys as specified by the parameters.
// Returns true if some keys have been generated.
func GenerateAcraKeys(params GenerateKeyParams, keyStore keystore.KeyMaking, defaultKeys DefaultKeyAction) (bool, error) {
	generateAcraWriter := params.GenerateAcraWriter()

	generateAcraBlocks := params.GenerateAcraBlocks()
	generateSearchHMAC := params.GenerateSearchHMAC()
	generatePoisonKeys := params.GeneratePoisonRecord()
	generateAuditLogKey := params.GenerateAuditLog()

	// If this is keystore initialization, allow the user to avoid specifying keys.
	// They will need all of them so just generate the default set.
	// However, if the keystore is already present then rotate only the specified keys.
	// Allow Acra EE to override this behavior with the "defaultKeys" setting.
	overrideDefaultSet := false
	switch defaultKeys {
	case GenerateOnInitialize:
		firstGeneration := params.KeystoreVersion() != ""
		explictKeys := params.SpecificKeysRequested()
		clientIDKnown := len(params.ClientID()) != 0
		overrideDefaultSet = firstGeneration && !explictKeys && clientIDKnown
	case GenerateDefaultsOverride:
		overrideDefaultSet = true
	}
	if overrideDefaultSet {
		generateAcraWriter = true
		generateAcraBlocks = true
		generateSearchHMAC = true
		generatePoisonKeys = true
		generateAuditLogKey = true
	}

	// If the user runs just "acra-keys generate" with no arguments and the configuration file
	// does not tell us the action either, we end up not doing anything useful.
	// Return this state to the caller so that we can at least tell the user than nothing changed
	// instead of keeping an ominous silence.
	didSomething := false

	if generateAcraWriter {
		err := keyStore.GenerateDataEncryptionKeys(params.ClientID())
		if err != nil {
			log.WithError(err).Error("Failed to generate client storage key")
			return didSomething, err
		}
		log.Info("Generated client storage key")
		didSomething = true
	}

	if params.GenerateNewZone() {
		id, publicKey, err := keyStore.GenerateZoneKey()
		if err != nil {
			log.WithError(err).Error("Failed to generate new zone")
			return didSomething, err
		}
		json, err := zone.DataToJSON(id, &keys.PublicKey{Value: publicKey})
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
		publicKey, err := keyStore.RotateZoneKey(zoneID)
		if err != nil {
			log.WithError(err).Error("Failed to rotate zone key")
			return didSomething, err
		}
		json, err := zone.DataToJSON(zoneID, &keys.PublicKey{Value: publicKey})
		if err != nil {
			log.WithError(err).Error("Failed to serialize zone parameters")
			return didSomething, err
		}
		fmt.Println(string(json))
		log.Info("Generated zone storage key")
		didSomething = true
	}
	if params.GenerateZoneSymmetricKey() {
		err := keyStore.RotateSymmetricZoneKey(params.ZoneID())
		if err != nil {
			log.WithError(err).Error("Failed to rotate zone key")
			return didSomething, err
		}
		log.Info("Generated zone storage symmetric key")
		didSomething = true
	}

	if generateAcraBlocks {
		err := keyStore.GenerateClientIDSymmetricKey(params.ClientID())
		if err != nil {
			log.WithError(err).Error("Failed to generate client storage symmetric key")
			return didSomething, err
		}
		log.Info("Generated client storage symmetric key")
		didSomething = true
	}

	if generateAuditLogKey {
		err := keyStore.GenerateLogKey()
		if err != nil {
			log.WithError(err).Error("Failed to generate HMAC key for audit log")
			return didSomething, err
		}
		log.Info("Generated HMAC key for audit log")
		didSomething = true
	}

	if generateSearchHMAC {
		err := keyStore.GenerateHmacKey(params.ClientID())
		if err != nil {
			log.WithError(err).Error("Failed to generate HMAC key for searchable encryption")
			return didSomething, err
		}
		log.Info("Generated HMAC key for searchable encryption")
		didSomething = true
	}

	if generatePoisonKeys {
		err := keyStore.GeneratePoisonSymmetricKey()
		if err != nil {
			log.WithError(err).Error("Failed to generate symmetric key for poison records")
			return didSomething, err
		}
		log.Info("Generated symmetric key for poison records")
		didSomething = true

		err = keyStore.GeneratePoisonKeyPair()
		if err != nil {
			log.WithError(err).Error("Failed to generate keypair for poison records")
			return didSomething, err
		}
		log.Info("Generated keypair for poison records")
	}

	return didSomething, nil
}
