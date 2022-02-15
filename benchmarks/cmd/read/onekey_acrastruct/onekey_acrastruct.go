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

package main

import (
	"fmt"
	"github.com/cossacklabs/acra/benchmarks/common"
	"github.com/cossacklabs/acra/benchmarks/write"
	"math/rand"
	"time"
)

func main() {
	db := common.Connect()
	fmt.Println("Generate rows")
	common.DropCreateWithoutZone(db)
	write.GenerateAcrastructRowsOneKey(common.GetServerOneKeyPublic(), db)
	db.Close()

	db = common.ConnectAcra()
	fmt.Println("Start benchmark")
	startTime := time.Now()
	var rowID int
	var data []byte
	for i := 0; i < common.RequestCount; i++ {
		id := rand.Intn(common.RowCount)
		err := db.QueryRow("SELECT id, data FROM test_without_zone WHERE id=$1+1;", &id).Scan(&rowID, &data)
		if err != nil {
			panic(err)
		}
	}
	endTime := time.Now()

	diff := endTime.Sub(startTime)
	fmt.Printf("Took %v sec\n", diff.Seconds())
	db.Close()
}
