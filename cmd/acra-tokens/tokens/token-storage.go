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

package tokens

import (
	"crypto/tls"
	"errors"
	"flag"
	"os"

	"github.com/cossacklabs/acra/cmd/args"
	"github.com/cossacklabs/acra/network"

	log "github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"

	"github.com/cossacklabs/acra/cmd"
	tokenCommon "github.com/cossacklabs/acra/pseudonymization/common"
	tokenStorage "github.com/cossacklabs/acra/pseudonymization/storage"
)

// CommonTokenStorageParameters is a mix-in of command line parameters for token storage construction.
type CommonTokenStorageParameters struct {
	boltDB string
}

// default open mode with which to initialize BoltDB storage
const boltDBOpenMode = os.FileMode(0600)

// Errors returned by token storage parameter parsing.
var (
	ErrInvalidTokenStorage = errors.New("token storage is configured incorrectly")
)

// Register registers token storage flags with the given flag set.
func (p *CommonTokenStorageParameters) Register(flags *flag.FlagSet) {
	flags.StringVar(&p.boltDB, "token_db", "", "path to BoltDB used for token data")
}

// BoltDBConfigured returns true if BoltDB is configured.
func (p *CommonTokenStorageParameters) BoltDBConfigured() bool {
	return p.boltDB != ""
}

// Validate token storage parameter set.
func (p *CommonTokenStorageParameters) Validate(extractor *args.ServiceExtractor) error {
	redisOptions := cmd.ParseRedisCLIParametersFromFlags(extractor, "")

	if p.BoltDBConfigured() && redisOptions.TokensConfigured() {
		log.Warn("Both --redis_host_port and --token_db cannot be used simultaneously")
		return ErrInvalidTokenStorage
	}
	if !p.BoltDBConfigured() && !redisOptions.TokensConfigured() {
		log.Warn("Either --redis_host_port or --token_db is required")
		return ErrInvalidTokenStorage
	}
	return nil
}

// Open a token storage based on the command-line configuration.
func (p *CommonTokenStorageParameters) Open(extractor *args.ServiceExtractor) (tokenCommon.TokenStorage, error) {
	if p.BoltDBConfigured() {
		db, err := bolt.Open(p.boltDB, boltDBOpenMode, nil)
		if err != nil {
			log.WithError(err).Warn("Cannot initialize BoltDB token storage")
			return nil, err
		}
		return tokenStorage.NewBoltDBTokenStorage(db), nil
	}
	if redisOptions := cmd.ParseRedisCLIParametersFromFlags(extractor, ""); redisOptions.KeysConfigured() {
		var redisTLSConfig *tls.Config
		var err error

		if redisOptions.TLSEnable {
			redisTLSConfig, err = network.NewTLSConfigByName(extractor, "redis", redisOptions.HostPort, network.ClientNameConstructorFunc())
			if err != nil {
				log.WithError(err).Errorln("Can't initialize tls config for redis client")
				return nil, err
			}
		}

		redisClient, err := tokenStorage.NewRedisClient(redisOptions.HostPort, redisOptions.Password, redisOptions.DBTokens, redisTLSConfig)
		if err != nil {
			log.WithError(err).Warn("Cannot initialize Redis client")
			return nil, err
		}

		storage, err := tokenStorage.NewRedisStorage(redisClient)
		if err != nil {
			log.WithError(err).Warn("Cannot initialize Redis token storage")
			return nil, err
		}
		return storage, nil
	}
	panic("unreachable: either BoltDB or Redis must be configured")
}
