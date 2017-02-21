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
	// ROW_COUNT num of rows that will be generated in each write benchmark
	ROW_COUNT = 10000
	// REQUEST_COUNT num of requests that will be done in each read benchmark
	REQUEST_COUNT = 10000
	// ZONE_COUNT num of zones which will be generated and used
	ZONE_COUNT = 100
	// MAX_DATA_LENGTH size of test random data that will be generated and inserted to db (before encrypting)
	MAX_DATA_LENGTH = 100 * 1024 // 100 kb
)
