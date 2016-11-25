package onekey_without_acrastruct

import (
	"fmt"
	"github.com/cossacklabs/acra/benchmarks/common"
	"github.com/cossacklabs/acra/benchmarks/config"
	"github.com/cossacklabs/acra/benchmarks/write"
	"math/rand"
	"time"
)

func main() {
	db := common.Connect()
	common.DropCreateWithoutZone(db)
	write.GenerateDataRows(db)

	start_time := time.Now()
	for i := 0; i < config.REQUEST_COUNT; i++ {
		id := rand.Intn(config.ROW_COUNT)
		_, err := db.Query("SELECT id, data FROM test_raw WHERE id=$1;", &id)
		if err != nil {
			panic(err)
		}
	}
	end_time := time.Now()

	diff := end_time.Sub(start_time)
	fmt.Printf("Took %v sec\n", diff.Seconds())
}
