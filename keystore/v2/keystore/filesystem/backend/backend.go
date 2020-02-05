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

// Package backend provides a common filesystem Backend interface for filesystem.KeyStore
// as well as some basic implementations of it.
//
// Backend treats "paths" like UNIX filesystems usually do.
// That is, components are separated by forward slash "/" character (filesystem.PathSeparator)
// and paths are expected to contain valid UTF-8 text.
// However, paths are not interpreted in any way and may actually contain arbitrary byte sequences,
// except for "/" and "\0" bytes that are treated specially.
package backend

import (
	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api"
)

// PathSeparator used in key paths.
const PathSeparator = api.PathSeparator

// Backend defines how KeyStore persists internal key data.
type Backend api.Backend
