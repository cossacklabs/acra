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
	"errors"
	"flag"
	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"
	"os"
	"strconv"

	goRedis "github.com/go-redis/redis/v7"
)

// RedisOptions keep command-line options related to Redis database configuration.
type RedisOptions struct {
	HostPort string
	Password string
	DBKeys   int
	DBTokens int
}

// Note that currently "keystore" and "token store" are expected to be located
// in the same Redis instance.

const (
	redisDefaultDB     = 0
	redisUnspecifiedDB = -1
)

var ErrIdenticalRedisDBs = errors.New("redis db params are identical")

var redisOptions RedisOptions

// RegisterRedisKeyStoreParameters registers CLI parameters for Redis (keystore).
func RegisterRedisKeyStoreParameters() {
	redisOptions.RegisterKeyStoreParametersWithPrefix("", "")
}

// ValidateRedisCLIOptions validate Redis CLI options.
func ValidateRedisCLIOptions() {
	if err := redisOptions.validateOptions(); err != nil {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongParam).Error(
			"Identical Redis DB parameters, one of redis_db_tokens or redis_db_keys should be provided")
		os.Exit(1)
	}
}

// RegisterKeyStoreParametersWithPrefix registers Redis keystore parameters with given prefix.
// Use empty prefix, or something like "src_" or "dst_", for example.
func (redis *RedisOptions) RegisterKeyStoreParametersWithPrefix(prefix string, description string) {
	redis.RegisterKeyStoreParameters(flag.CommandLine, prefix, description)
}

// RegisterKeyStoreParameters registers Redis keystore parameters with given flag set and prefix.
// Use empty prefix, or something like "src_" or "dst_", for example.
func (redis *RedisOptions) RegisterKeyStoreParameters(flags *flag.FlagSet, prefix string, description string) {
	if description != "" {
		description = " (" + description + ")"
	}
	if flags.Lookup(prefix+"redis_host_port") == nil {
		flags.StringVar(&redis.HostPort, prefix+"redis_host_port", "", "<host>:<port> used to connect to Redis"+description)
		flags.StringVar(&redis.Password, prefix+"redis_password", "", "Password to Redis database"+description)
	}
	flags.IntVar(&redis.DBKeys, prefix+"redis_db_keys", redisDefaultDB, "Number of Redis database for keys"+description)
	redis.checkBothKeyAndToken(prefix, flags)
}

// RegisterRedisTokenStoreParameters registers CLI parameters for Redis (token store).
func RegisterRedisTokenStoreParameters() {
	redisOptions.RegisterTokenStoreParametersWithPrefix(flag.CommandLine, "", "")
}

// RegisterTokenStoreParametersWithPrefix registers Redis token store parameters with given prefix.
// Use empty prefix, or something like "src_" or "dst_", for example.
func (redis *RedisOptions) RegisterTokenStoreParametersWithPrefix(flags *flag.FlagSet, prefix string, description string) {
	if description != "" {
		description = " (" + description + ")"
	}
	if flags.Lookup(prefix+"redis_host_port") == nil {
		flags.StringVar(&redis.HostPort, prefix+"redis_host_port", "", "<host>:<port> used to connect to Redis"+description)
		flags.StringVar(&redis.Password, prefix+"redis_password", "", "Password to Redis database"+description)
	}
	flags.IntVar(&redis.DBTokens, prefix+"redis_db_tokens", redisDefaultDB, "Number of Redis database for tokens"+description)
	redis.checkBothKeyAndToken(prefix, flags)
}

// If a binary can use both key and token DB, have the user specify them explicitly.
func (redis *RedisOptions) checkBothKeyAndToken(prefix string, flags *flag.FlagSet) {
	keys := flags.Lookup(prefix + "redis_db_keys")
	tokens := flags.Lookup(prefix + "redis_db_tokens")
	if keys != nil && tokens != nil {
		keys.DefValue = strconv.Itoa(redisUnspecifiedDB)
		tokens.DefValue = strconv.Itoa(redisUnspecifiedDB)
		redis.DBKeys = redisUnspecifiedDB
		redis.DBTokens = redisUnspecifiedDB
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

// GetRedisParameters returns a copy of RedisOptions parsed from the command line.
func GetRedisParameters() RedisOptions {
	return redisOptions
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
func (redis *RedisOptions) KeysOptions() *goRedis.Options {
	return &goRedis.Options{
		Addr:     redis.HostPort,
		Password: redis.Password,
		DB:       redis.DBKeys,
	}
}
