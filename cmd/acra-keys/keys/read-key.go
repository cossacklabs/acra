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
	"strings"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	log "github.com/sirupsen/logrus"
)

// SupportedReadKeyKinds is a list of keys supported by `read-key` subcommand.
var SupportedReadKeyKinds = []string{
	KeyPoisonPublic,
	KeyPoisonPrivate,
	KeyStoragePublic,
	KeyStoragePrivate,
	KeyZonePublic,
	KeyZonePrivate,
}

// Key parameter errors:
var (
	ErrMissingClientID = errors.New("client ID not specified")
	ErrMissingZoneID   = errors.New("zone ID not specified")
	ErrUnknownKeyKind  = errors.New("unknown key kind")
)

// ReadKeyParams are parameters of "acra-keys read" subcommand.
type ReadKeyParams interface {
	ReadKeyKind() string
	ClientID() []byte
	ZoneID() []byte
}

// ReadKeySubcommand is the "acra-keys read" subcommand.
type ReadKeySubcommand struct {
	CommonKeyStoreParameters
	FlagSet *flag.FlagSet

	readKeyKind string
	clientID    string
	zoneID      string
}

// RegisterFlags registers command-line flags of "acra-keys read".
func (p *ReadKeySubcommand) RegisterFlags() {
	p.FlagSet = flag.NewFlagSet(CmdReadKey, flag.ContinueOnError)
	p.CommonKeyStoreParameters.Register(p.FlagSet)
	p.FlagSet.StringVar(&p.clientID, "client_id", "", "client ID for which to retrieve key")
	p.FlagSet.StringVar(&p.zoneID, "zone_id", "", "zone ID for which to retrieve key")
	p.FlagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": read and print key material in plaintext\n", CmdReadKey)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...] <key-kind>\n\n", os.Args[0], CmdReadKey)
		fmt.Fprintf(os.Stderr, "Supported key kinds:\n  %s\n", strings.Join(SupportedReadKeyKinds, ", "))
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(p.FlagSet)
	}
}

// Parse command-line parameters of the subcommand.
func (p *ReadKeySubcommand) Parse(arguments []string) error {
	err := cmd.ParseFlagsWithConfig(p.FlagSet, arguments, DefaultConfigPath, ServiceName)
	if err != nil {
		return err
	}
	args := p.FlagSet.Args()
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
	p.readKeyKind = args[0]
	switch p.readKeyKind {
	case KeyTransportConnector, KeyTransportServer, KeyTransportTranslator, KeyStoragePublic, KeyStoragePrivate:
		if p.clientID == "" {
			log.Errorf("\"%s\" key requires --client_id", p.readKeyKind)
			return ErrMissingClientID
		}
	case KeyZonePublic, KeyZonePrivate:
		if p.zoneID == "" {
			log.Errorf("\"%s\" key requires --zone_id", p.readKeyKind)
			return ErrMissingZoneID
		}
	}
	if p.clientID != "" && p.zoneID != "" {
		log.Errorf("--client_id and --zone_id cannot be used simultaneously")
		return ErrMultipleKeyKinds
	}
	return nil
}

// ReadKeyKind returns kind of the requested key.
func (p *ReadKeySubcommand) ReadKeyKind() string {
	return p.readKeyKind
}

// ClientID returns client ID of the requested key.
func (p *ReadKeySubcommand) ClientID() []byte {
	return []byte(p.clientID)
}

// ZoneID returns zone ID of the requested key.
func (p *ReadKeySubcommand) ZoneID() []byte {
	return []byte(p.zoneID)
}

// ReadKeyBytes returns plaintext bytes of the requsted key.
func ReadKeyBytes(params ReadKeyParams, keyStore keystore.ServerKeyStore) ([]byte, error) {
	kind := params.ReadKeyKind()
	switch kind {
	case KeyPoisonPublic:
		keypair, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			log.WithError(err).Error("Cannot read poison record key pair")
			return nil, err
		}
		return keypair.Public.Value, nil

	case KeyPoisonPrivate:
		keypair, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			log.WithError(err).Error("Cannot read poison record key pair")
			return nil, err
		}
		return keypair.Private.Value, nil

	case KeyStoragePublic:
		key, err := keyStore.GetClientIDEncryptionPublicKey(params.ClientID())
		if err != nil {
			log.WithError(err).Error("Cannot read client storage public key")
			return nil, err
		}
		return key.Value, nil

	case KeyStoragePrivate:
		key, err := keyStore.GetServerDecryptionPrivateKey(params.ClientID())
		if err != nil {
			log.WithError(err).Error("Cannot read client storage private key")
			return nil, err
		}
		return key.Value, nil

	case KeyZonePublic:
		key, err := keyStore.GetZonePublicKey(params.ZoneID())
		if err != nil {
			log.WithError(err).Error("Cannot read zone storage public key")
			return nil, err
		}
		return key.Value, nil

	case KeyZonePrivate:
		key, err := keyStore.GetZonePrivateKey(params.ZoneID())
		if err != nil {
			log.WithError(err).Error("Cannot read zone storage private key")
			return nil, err
		}
		return key.Value, nil

	default:
		log.WithField("expected", SupportedReadKeyKinds).Errorf("Unknown key kind: %s", kind)
		return nil, ErrUnknownKeyKind
	}
}
