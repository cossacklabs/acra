package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/cossacklabs/acra/acrawriter"
	"github.com/cossacklabs/acra/benchmarks/common"
	"github.com/cossacklabs/acra/benchmarks/config"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io/ioutil"
	"time"
)

var zones = make([]ZoneData, config.ZONE_COUNT)

type ZoneData struct {
	Id        []byte
	PublicKey *keys.PublicKey
}

func load_zones() {
	abs_dir, err := utils.AbsPath("src/github.com/cossacklabs/acra/benchmarks")
	if err != nil{panic(err)}
	dumped_zone_data, err := ioutil.ReadFile(fmt.Sprintf("%v/public_keys.txt", abs_dir))
	for i, zone_data := range bytes.Split(dumped_zone_data, []byte("\n")) {
		json_data := ZoneData{}
		err = json.Unmarshal(zone_data, &json_data)
		if err != nil {
			panic(err)
		}
		zones[i] = json_data
	}
}

// Took 107.102318501 sec with generating zones
func main() {
	db := common.Connect()
	common.DropCreateWithZone(db)

	start_time := time.Now()
	load_zones()
	for count := 0; count < config.ROW_COUNT; count++ {
		data, err := common.GenerateData()
		if err != nil {
			panic(err)
		}

		zone_data := zones[count%config.ZONE_COUNT]
		acrastruct, err := acrawriter.CreateAcrastruct(data, zone_data.PublicKey, zone_data.Id)
		if err != nil {
			panic(err)
		}
		_, err = db.Exec("INSERT INTO test_with_zone(zone, data) VALUES ($1, $2);", &zone_data.Id, &acrastruct)
		if err != nil {
			panic(err)
		}
	}
	end_time := time.Now()
	diff := end_time.Sub(start_time)
	fmt.Printf("Took %v sec\n", diff.Seconds())
}
