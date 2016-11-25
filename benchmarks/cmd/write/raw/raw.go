package main

import (
	"fmt"
	"github.com/cossacklabs/acra/benchmarks/common"
	"github.com/cossacklabs/acra/benchmarks/write"
	"time"
)

//Took 77.696991835 sec
func main() {
	db := common.Connect()
	common.DropCreateRaw(db)
	start_time := time.Now()
	write.GenerateDataRows(db)
	end_time := time.Now()
	diff := end_time.Sub(start_time)
	fmt.Printf("Took %v sec\n", diff.Seconds())
}
