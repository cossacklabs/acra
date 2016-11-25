package main

import (
	"fmt"
	"github.com/cossacklabs/acra/benchmarks/common"
	"github.com/cossacklabs/acra/benchmarks/config"
	"math/rand"
	"time"
)

func main() {
	db := common.Connect()
	fmt.Println("Generate rows")
	common.LoadDataWithoutZone(db)
	db.Close()

	db = common.ConnectAcra()
	fmt.Println("Start benchmark")
	start_time := time.Now()
	for i := 0; i < config.REQUEST_COUNT; i++ {
		id := rand.Intn(config.ROW_COUNT)
		fmt.Printf("Id: %v\n", id)
		results, err := db.Query("SELECT id, data FROM test_without_zone WHERE id=$1;", &id)
		if err != nil {
			panic(err)
		}
		results.Close()
	}
	end_time := time.Now()

	diff := end_time.Sub(start_time)
	fmt.Printf("Took %v sec\n", diff.Seconds())
}
