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

package cmd

import (
	"crypto/tls"
	"errors"
	"flag"
	"os"
	"strconv"

	"github.com/cossacklabs/acra/network"

	goRedis "github.com/go-redis/redis/v7"
	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/logging"
)

// RedisOptions keep command-line options related to Redis database configuration.
type RedisOptions struct {
	HostPort  string
	Password  string
	DBKeys    int
	DBTokens  int
	TLSEnable bool
}

// Note that currently "keystore" and "token store" are expected to be located
// in the same Redis instance.

const (
	redisDefaultDB     = 0
	redisUnspecifiedDB = -1
)

// ErrIdenticalRedisDBs redis DBs related error
var ErrIdenticalRedisDBs = errors.New("redis db params are identical")

// RegisterRedisKeystoreParameters registers Redis keystore parameters with given CommandLine flags and empty prefix
func RegisterRedisKeystoreParameters() {
	RegisterRedisKeystoreParametersWithPrefix(flag.CommandLine, "", "")
}

// ParseRedisCLIParameters parse RedisOptions from CommandLine flags
func ParseRedisCLIParameters() *RedisOptions {
	return ParseRedisCLIParametersFromFlags(flag.CommandLine, "")
}

// RegisterRedisTokenStoreParameters registers Redis TokenStore parameters with given CommandLine flags and empty prefix
func RegisterRedisTokenStoreParameters() {
	RegisterRedisTokenStoreParametersWithPrefix(flag.CommandLine, "", "")
}

// RegisterRedisKeystoreParametersWithPrefix registers Redis keystore parameters with given flag set and prefix.
// Use empty prefix, or something like "src_" or "dst_", for example.
func RegisterRedisKeystoreParametersWithPrefix(flags *flag.FlagSet, prefix string, description string) {
	if description != "" {
		description = " (" + description + ")"
	}

	if flags.Lookup(prefix+"redis_host_port") == nil {
		flags.String(prefix+"redis_host_port", "", "<host>:<port> used to connect to Redis"+description)
		flags.String(prefix+"redis_password", "", "Password to Redis database"+description)
		flags.Bool(prefix+"redis_tls_enable", false, "Use TLS to connect to Redis"+description)
	}
	if flags.Lookup(prefix+network.ClientNameConstructorFunc()("redis", "cert", "")) == nil {
		network.RegisterTLSArgsForService(flags, true, prefix+"redis", network.ClientNameConstructorFunc())
	}
	flags.Int(prefix+"redis_db_keys", redisDefaultDB, "Number of Redis database for keys"+description)
	checkBothKeyAndToken(flags, prefix)
}

// RegisterRedisTokenStoreParametersWithPrefix registers Redis keystore parameters with given flag set and prefix.
// Use empty prefix, or something like "src_" or "dst_", for example.
func RegisterRedisTokenStoreParametersWithPrefix(flags *flag.FlagSet, prefix string, description string) {
	if description != "" {
		description = " (" + description + ")"
	}

	if flags.Lookup(prefix+"redis_host_port") == nil {
		flags.String(prefix+"redis_host_port", "", "<host>:<port> used to connect to Redis"+description)
		flags.String(prefix+"redis_password", "", "Password to Redis database"+description)
		flags.Bool(prefix+"redis_tls_enable", false, "Use TLS to connect to Redis"+description)
	}
	if flags.Lookup(prefix+network.ClientNameConstructorFunc()("redis", "cert", "")) == nil {
		network.RegisterTLSArgsForService(flags, true, prefix+"redis", network.ClientNameConstructorFunc())
	}
	flags.Int(prefix+"redis_db_tokens", redisDefaultDB, "Number of Redis database for tokens"+description)
	checkBothKeyAndToken(flags, prefix)
}

// If a binary can use both key and token DB, have the user specify them explicitly.
func checkBothKeyAndToken(flags *flag.FlagSet, prefix string) {
	keys := flags.Lookup(prefix + "redis_db_keys")
	tokens := flags.Lookup(prefix + "redis_db_tokens")
	if keys != nil && tokens != nil {
		keys.DefValue = strconv.Itoa(redisUnspecifiedDB)
		tokens.DefValue = strconv.Itoa(redisUnspecifiedDB)
	}
}

// ParseRedisCLIParametersFromFlags parse CLI args from FlagSet
func ParseRedisCLIParametersFromFlags(flags *flag.FlagSet, prefix string) *RedisOptions {
	redisOptions := RedisOptions{}

	if f := flags.Lookup(prefix + "redis_host_port"); f != nil {
		redisOptions.HostPort = f.Value.String()
	}
	if f := flags.Lookup(prefix + "redis_password"); f != nil {
		redisOptions.Password = f.Value.String()
	}
	if f := flags.Lookup(prefix + "redis_db_tokens"); f != nil {
		getter, ok := f.Value.(flag.Getter)
		if !ok {
			log.Fatal("Can't cast flag's Value to Getter")
		}
		val, ok := getter.Get().(int)
		if !ok {
			log.WithField("value", getter.Get()).Fatalf("Can't cast %s to integer value", prefix+"redis_db_tokens")
		}
		redisOptions.DBTokens = val
	}

	if f := flags.Lookup(prefix + "redis_tls_enable"); f != nil {
		v, err := strconv.ParseBool(f.Value.String())
		if err != nil {
			log.WithField("value", f.Value.String).Fatalf("Can't cast %s to boolean value", prefix+"redis_tls_enable")
		}
		redisOptions.TLSEnable = v
	}
	if f := flags.Lookup(prefix + "redis_db_keys"); f != nil {
		getter, ok := f.Value.(flag.Getter)
		if !ok {
			log.Fatal("Can't cast flag's Value to Getter")
		}
		val, ok := getter.Get().(int)
		if !ok {
			log.WithField("value", getter.Get()).Fatalf("Can't cast %s to integer value", prefix+"redis_db_keys")
		}
		redisOptions.DBKeys = val
	}

	return &redisOptions
}

// ValidateRedisCLIOptions validate Redis CLI options.
func ValidateRedisCLIOptions(redisOptions *RedisOptions) {
	if err := redisOptions.validateOptions(); err != nil {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongParam).Errorln(
			"Identical Redis DB parameters, one of redis_db_tokens or redis_db_keys should be provided")
		os.Exit(1)
	}
}

// validateOptions check weather DBTokens and DBKeys are not similar
func (redis *RedisOptions) validateOptions() error {
	if redis.HostPort == "" {
		return nil
	}

	if redis.DBTokens == redis.DBKeys {
		return ErrIdenticalRedisDBs
	}
	return nil
}

// KeysConfigured returns true if Redis is configured for key storage.
func (redis *RedisOptions) KeysConfigured() bool {
	return redis.HostPort != "" && redis.DBKeys != redisUnspecifiedDB
}

// TokensConfigured returns true if Redis is configured for token storage.
func (redis *RedisOptions) TokensConfigured() bool {
	return redis.HostPort != "" && redis.DBTokens != redisUnspecifiedDB
}

// KeysOptions returns Redis connection configuration for key storage.
func (redis *RedisOptions) KeysOptions(flags *flag.FlagSet) (*goRedis.Options, error) {
	var tlsConfig *tls.Config
	var err error
	if redis.TLSEnable {
		tlsConfig, err = network.NewTLSConfigByName(flags, "redis", redis.HostPort, network.ClientNameConstructorFunc())
		if err != nil {
			return nil, err
		}
	}
	return &goRedis.Options{
		Addr:      redis.HostPort,
		Password:  redis.Password,
		DB:        redis.DBKeys,
		TLSConfig: tlsConfig,
	}, nil
}
