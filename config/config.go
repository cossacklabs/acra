// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package config

import (
	"errors"
)

const (
	HEX_BYTEA_FORMAT    int8 = 1
	ESCAPE_BYTEA_FORMAT int8 = 2
)

type Config struct {
	proxy_commands_port int
	bytea_format        int8
	db_port             int
	proxy_port          int
	db_host             string
	proxy_host          string
	keys_dir            string
	script_on_poison    string
	stop_on_poison      bool
	with_zone           bool
	whole_match         bool
	server_id           []byte
	poison_key          []byte
}

func NewConfig() *Config {
	return &Config{with_zone: false, stop_on_poison: false, whole_match: true}
}
func (config *Config) SetPoisonKey(key []byte) {
	config.poison_key = key
}
func (config *Config) GetPoisonKey() []byte {
	return config.poison_key
}
func (config *Config) SetScriptOnPoison(script_path string) {
	config.script_on_poison = script_path
}
func (config *Config) GetScriptOnPoison() string {
	return config.script_on_poison
}
func (config *Config) SetStopOnPoison(stop bool) {
	config.stop_on_poison = stop
}
func (config *Config) GetStopOnPoison() bool {
	return config.stop_on_poison
}
func (config *Config) GetWithZone() bool {
	return config.with_zone
}
func (config *Config) SetWithZone(wz bool) {
	config.with_zone = wz
}
func (config *Config) GetProxyHost() string {
	return config.proxy_host
}
func (config *Config) SetProxyHost(host string) error {
	config.proxy_host = host
	return nil
}
func (config *Config) GetProxyPort() int {
	return config.proxy_port
}
func (config *Config) GetProxyCommandsPort() int {
	return config.proxy_commands_port
}
func (config *Config) SetProxyPort(port int) error {
	config.proxy_port = port
	return nil
}
func (config *Config) SetProxyCommandsPort(port int) error {
	config.proxy_commands_port = port
	return nil
}
func (config *Config) GetDBHost() string {
	return config.db_host
}
func (config *Config) SetDBHost(host string) error {
	config.db_host = host
	return nil
}
func (config *Config) GetDBPort() int {
	return config.db_port
}
func (config *Config) SetDBPort(port int) error {
	config.db_port = port
	return nil
}
func (config *Config) SetByteaFormat(format int8) error {
	if format != HEX_BYTEA_FORMAT && format != ESCAPE_BYTEA_FORMAT {
		return errors.New("Incorrect bytea format")
	}
	config.bytea_format = format
	return nil
}
func (config *Config) GetByteaFormat() int8 {
	return config.bytea_format
}
func (config *Config) GetKeysDir() string {
	return config.keys_dir
}
func (config *Config) SetKeysDir(keys_dir string) error {
	config.keys_dir = keys_dir
	return nil
}
func (config *Config) GetServerId() []byte {
	return config.server_id
}
func (config *Config) SetServerId(server_id []byte) error {
	config.server_id = server_id
	return nil
}
func (config *Config) GetWholeMatch() bool {
	return config.whole_match
}
func (config *Config) SetWholeMatch(value bool) {
	config.whole_match = value
}
