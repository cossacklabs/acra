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
	"io"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/cmd/args"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
)

// SupportedReadKeyKinds is a list of keys supported by `read-key` subcommand.
var SupportedReadKeyKinds = []string{
	keystore.KeyPoisonPublic,
	keystore.KeyPoisonPrivate,
	keystore.KeyStoragePublic,
	keystore.KeyStoragePrivate,
	keystore.KeySymmetric,
}

// Key parameter errors:
var (
	ErrMissingClientID             = errors.New("client ID not specified")
	ErrUnknownKeyKind              = errors.New("unknown key kind")
	ErrMissingKeyPart              = errors.New("key part not specified")
	ErrExtraKeyPart                = errors.New("both key parts specified")
	ErrMissingTLSCertPath          = errors.New("TLS certificate path not specified")
	ErrDuplicatedTLSCertPathFlags  = errors.New("passed --tls_cert (deprecated since 0.96.0) and --tls_client_id_cert simultaneously")
	ErrClientIDWithTLSCertProvided = errors.New("client ID and TLS certificate path are both provided")
)

// ReadKeyParams are parameters of "acra-keys read" subcommand.
type ReadKeyParams interface {
	ReadKeyKind() string
	ClientID() []byte
}

// ReadKeySubcommand is the "acra-keys read" subcommand.
type ReadKeySubcommand struct {
	CommonKeyStoreParameters
	FlagSet   *flag.FlagSet
	extractor *args.ServiceExtractor

	public, private bool

	readKeyKind string
	contextID   []byte
	outWriter   io.Writer
}

// GetExtractor returns ServiceParamsExtractor extractor
func (p *ReadKeySubcommand) GetExtractor() *args.ServiceExtractor {
	return p.extractor
}

// Name returns the name of this subcommand.
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
	network.RegisterTLSBaseArgs(p.FlagSet)
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
	err := cmd.ParseFlags(p.FlagSet, arguments)
	if err != nil {
		return err
	}

	serviceConfig, err := cmd.ParseConfig(DefaultConfigPath, ServiceName)
	if err != nil {
		return err
	}
	p.extractor = args.NewServiceExtractor(p.FlagSet, serviceConfig)

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
	case keystore.KeySymmetric:
		p.readKeyKind = coarseKind
		p.contextID = id

	case keystore.KeyPoisonKeypair:
		if err := p.validateKeyParts(); err != nil {
			return err
		}
		if p.private {
			p.readKeyKind = keystore.KeyPoisonPrivate
		} else {
			p.readKeyKind = keystore.KeyPoisonPublic
		}

	case keystore.KeyStorageKeypair:
		if err := p.validateKeyParts(); err != nil {
			return err
		}
		if p.private {
			p.readKeyKind = keystore.KeyStoragePrivate
		} else {
			p.readKeyKind = keystore.KeyStoragePublic
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
	p.PrintKeyCommand(p, keyStore)
}

// ReadKeyKind returns kind of the requested key.
func (p *ReadKeySubcommand) ReadKeyKind() string {
	return p.readKeyKind
}

// ClientID returns client ID of the requested key.
func (p *ReadKeySubcommand) ClientID() []byte {
	return p.contextID
}

// PrintKeyCommand implements the "read" command.
func (p *ReadKeySubcommand) PrintKeyCommand(params ReadKeyParams, keyStore keystore.ServerKeyStore) {
	keyBytes, err := ReadKeyBytes(params, keyStore)
	if err != nil {
		log.WithError(err).Fatal("Failed to read key")
	}
	defer utils.ZeroizeSymmetricKey(keyBytes)
	// allow to override writer for tests purpose with IDEA support
	// https://github.com/go-lang-plugin-org/go-lang-idea-plugin/issues/2439
	// IDEA marks test-cases as terminated if something in tests writes to stdout due to using json format and invalid output
	// https://github.com/golang/go/issues/23036
	// but by default it should write to StdOut to be able to pipe out output to next command
	var writer io.Writer = os.Stdout
	if p.outWriter != nil {
		writer = p.outWriter
	}
	_, err = writer.Write(keyBytes)
	if err != nil {
		log.WithError(err).Fatal("Failed to write key")
	}
}

// ReadKeyBytes returns plaintext bytes of the requsted key.
func ReadKeyBytes(params ReadKeyParams, keyStore keystore.ServerKeyStore) ([]byte, error) {
	kind := params.ReadKeyKind()
	switch kind {
	case keystore.KeyPoisonPublic:
		keypair, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			log.WithError(err).Error("Cannot read poison record key pair")
			return nil, err
		}
		return keypair.Public.Value, nil

	case keystore.KeyPoisonPrivate:
		keypair, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			log.WithError(err).Error("Cannot read poison record key pair")
			return nil, err
		}
		return keypair.Private.Value, nil

	case keystore.KeyStoragePublic:
		key, err := keyStore.GetClientIDEncryptionPublicKey(params.ClientID())
		if err != nil {
			log.WithError(err).Error("Cannot read client storage public key")
			return nil, err
		}
		return key.Value, nil

	case keystore.KeyStoragePrivate:
		key, err := keyStore.GetServerDecryptionPrivateKey(params.ClientID())
		if err != nil {
			log.WithError(err).Error("Cannot read client storage private key")
			return nil, err
		}
		return key.Value, nil

	case keystore.KeySymmetric:
		key, err := keyStore.GetClientIDSymmetricKey(params.ClientID())
		if err != nil {
			log.WithError(err).Error("Cannot read client symmetric key")
			return nil, err
		}
		return key, nil

	default:
		log.WithField("expected", SupportedReadKeyKinds).Errorf("Unknown key kind: %s", kind)
		return nil, ErrUnknownKeyKind
	}
}
