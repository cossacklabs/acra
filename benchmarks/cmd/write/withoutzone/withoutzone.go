package main

import (
	"fmt"
	"github.com/cossacklabs/acra/benchmarks/common"
	"github.com/cossacklabs/acra/benchmarks/write"
	"time"
)

//Took 109.946664497 sec
func main() {
	db := common.Connect()
	common.DropCreateWithoutZone(db)

	write.CheckOneKey()
	public_key := write.GetPublicOneKey()

	start_time := time.Now()
	write.GenerateAcrastructRowsOneKey(public_key, db)
	end_time := time.Now()

	diff := end_time.Sub(start_time)
	fmt.Printf("Took %v sec\n", diff.Seconds())
}
