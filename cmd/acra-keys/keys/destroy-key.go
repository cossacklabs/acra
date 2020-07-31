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
	"strings"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	log "github.com/sirupsen/logrus"
)

// SupportedDestroyKeyKinds is a list of keys supported by `destroy-key` subcommand.
var SupportedDestroyKeyKinds = []string{
	KeyTransportConnector,
	KeyTransportServer,
	KeyTransportTranslator,
}

// DestroyKeyParams are parameters of "acra-keys destroy" subcommand.
type DestroyKeyParams interface {
	DestroyKeyKind() string
	ClientID() []byte
}

// DestroyKeySubcommand is the "acra-keys destroy" subcommand.
type DestroyKeySubcommand struct {
	CommonKeyStoreParameters
	FlagSet *flag.FlagSet

	destroyKeyKind string
	clientID       string
}

// RegisterFlags registers command-line flags of "acra-keys read".
func (p *DestroyKeySubcommand) RegisterFlags() {
	p.FlagSet = flag.NewFlagSet(CmdReadKey, flag.ContinueOnError)
	p.CommonKeyStoreParameters.Register(p.FlagSet)
	p.FlagSet.StringVar(&p.clientID, "client_id", "", "client ID for which to destroy key")
	p.FlagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": destroy key material\n", CmdDestroyKey)
		fmt.Fprintf(os.Stderr, "\n\t%s %s [options...] <key-kind>\n\n", os.Args[0], CmdDestroyKey)
		fmt.Fprintf(os.Stderr, "Supported key kinds:\n  %s\n", strings.Join(SupportedDestroyKeyKinds, ", "))
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(p.FlagSet)
	}
}

// DestroyKeyKind returns requested kind of the key to destroy.
func (p *DestroyKeySubcommand) DestroyKeyKind() string {
	return p.destroyKeyKind
}

// ClientID returns client ID of the requested key.
func (p *DestroyKeySubcommand) ClientID() []byte {
	return []byte(p.clientID)
}

// DestroyKey destroys data of the requsted key.
func DestroyKey(params DestroyKeyParams, keyStore keystore.KeyMaking) error {
	kind := params.DestroyKeyKind()
	switch kind {
	case KeyTransportConnector:
		err := keyStore.DestroyConnectorKeypair(params.ClientID())
		if err != nil {
			log.WithError(err).Error("Cannot destroy AcraConnector transport key pair")
			return err
		}
		return nil

	case KeyTransportServer:
		err := keyStore.DestroyServerKeypair(params.ClientID())
		if err != nil {
			log.WithError(err).Error("Cannot destroy AcraServer transport key pair")
			return err
		}
		return nil

	case KeyTransportTranslator:
		err := keyStore.DestroyTranslatorKeypair(params.ClientID())
		if err != nil {
			log.WithError(err).Error("Cannot destroy AcraTranslator transport key pair")
			return err
		}
		return nil

	default:
		log.WithField("expected", SupportedDestroyKeyKinds).Errorf("Unknown key kind: %s", kind)
		return ErrUnknownKeyKind
	}
}
