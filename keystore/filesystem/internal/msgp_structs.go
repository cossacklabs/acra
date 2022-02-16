// Copyright 2022, Cossack Labs Limited
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

package internal

// https://github.com/tinylib/msgp/wiki/Using-the-Code-Generator
//go:generate msgp -tests=false -io=false

// HistoricalPaths struct for Msgpack serializer/deserializer used to cache historical filepaths to rotated keys
type HistoricalPaths struct {
	Paths []string
}
