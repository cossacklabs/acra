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

const (
	// RowCount num of rows that will be generated in each write benchmark
	RowCount = 10000
	// RequestCount num of requests that will be done in each read benchmark
	RequestCount = 10000
	// ZoneCount num of zones which will be generated and used
	ZoneCount = 100
	// MaxDataLength size of test random data that will be generated and inserted to db (before encrypting)
	MaxDataLength = 100 * 1024 // 100 kb
)
