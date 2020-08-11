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

// Package main is entry point for `acra-keys` utility.
//
// It can access and maniplulate key stores:
//
//   - list keys
//   - export keys
//   - import keys
//   - migrate key stores
//   - read key data
//   - destroy keys
package main

import (
	"github.com/cossacklabs/acra/cmd/acra-keys/keys"
)

func main() {
	subcommands := []keys.Subcommand{
		&keys.ListKeySubcommand{},
		&keys.ExportKeysSubcommand{},
		&keys.ImportKeysSubcommand{},
		&keys.MigrateKeysSubcommand{},
		&keys.ReadKeySubcommand{},
		&keys.DestroyKeySubcommand{},
	}
	subcommand := keys.ParseParameters(subcommands)
	if subcommand != nil {
		subcommand.Execute()
	}
}
