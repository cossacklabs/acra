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
	ErrMissingClientID             = errors.New("client ID not specified")
	ErrMissingZoneID               = errors.New("zone ID not specified")
	ErrUnknownKeyKind              = errors.New("unknown key kind")
	ErrMissingKeyPart              = errors.New("key part not specified")
	ErrExtraKeyPart                = errors.New("both key parts specified")
	ErrMissingTLSCertPath          = errors.New("TLS certificate path not specified")
	ErrClientIDWithTLSCertProvided = errors.New("client ID and TLS certificate path are both provided")
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

	public, private bool

	readKeyKind string
	contextID   []byte
}

// Name returns the same of this subcommand.
func (p *ReadKeySubcommand) Name() string {
	return CmdReadKey
}

// GetFlagSet returns flag set of this subcommand.
func (p *ReadKeySubcommand) GetFlagSet() *flag.FlagSet {
	return p.FlagSet
}

// RegisterFlags registers command-line flags of "acra-keys read".
func (p *ReadKeySubcommand) RegisterFlags() {
	p.FlagSet = flag.NewFlagSet(CmdReadKey, flag.ContinueOnError)
	p.CommonKeyStoreParameters.Register(p.FlagSet)
	p.FlagSet.BoolVar(&p.public, "public", false, "read public key of the keypair")
	p.FlagSet.BoolVar(&p.private, "private", false, "read private key of the keypair")
	p.FlagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": read and print key material in plaintext\n", CmdReadKey)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...] <key-ID>\n\n", os.Args[0], CmdReadKey)
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
	coarseKind, id, err := ParseKeyKind(args[0])
	if err != nil {
		return err
	}
	switch coarseKind {
	case KeyTransportConnector, KeyTransportServer, KeyTransportTranslator:
		p.readKeyKind = coarseKind
		p.contextID = id

	case KeyPoisonKeypair:
		if err := p.validateKeyParts(); err != nil {
			return err
		}
		if p.private {
			p.readKeyKind = KeyPoisonPrivate
		} else {
			p.readKeyKind = KeyPoisonPublic
		}

	case KeyStorageKeypair:
		if err := p.validateKeyParts(); err != nil {
			return err
		}
		if p.private {
			p.readKeyKind = KeyStoragePrivate
		} else {
			p.readKeyKind = KeyStoragePublic
		}
		p.contextID = id

	case KeyZoneKeypair:
		if err := p.validateKeyParts(); err != nil {
			return err
		}
		if p.private {
			p.readKeyKind = KeyZonePrivate
		} else {
			p.readKeyKind = KeyZonePublic
		}
		p.contextID = id

	default:
		return ErrUnknownKeyKind
	}
	return nil
}

func (p *ReadKeySubcommand) validateKeyParts() error {
	if p.private && p.public {
		log.Warn("Options --private and --public cannot be used simultaneously")
		return ErrExtraKeyPart
	}
	if !(p.private || p.public) {
		log.Warn("Missing --private or --public for a key pair")
		return ErrMissingKeyPart
	}
	return nil
}

// Execute this subcommand.
func (p *ReadKeySubcommand) Execute() {
	keyStore, err := OpenKeyStoreForReading(p)
	if err != nil {
		log.WithError(err).Fatal("Failed to open keystore")
	}
	PrintKeyCommand(p, keyStore)
}

// ReadKeyKind returns kind of the requested key.
func (p *ReadKeySubcommand) ReadKeyKind() string {
	return p.readKeyKind
}

// ClientID returns client ID of the requested key.
func (p *ReadKeySubcommand) ClientID() []byte {
	return p.contextID
}

// ZoneID returns zone ID of the requested key.
func (p *ReadKeySubcommand) ZoneID() []byte {
	return p.contextID
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
