package write

import (
	"database/sql"
	"fmt"
	"github.com/cossacklabs/acra/acrawriter"
	"github.com/cossacklabs/acra/benchmarks/common"
	"github.com/cossacklabs/acra/benchmarks/config"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"os"
)

func CheckOneKey() {
	keys_path := []string{
		"src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey",
		"src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey.pub",
		"src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey_server",
		"src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey_server.pub",
	}
	for _, key := range keys_path {
		exists, err := utils.FileExists(key)
		if err != nil {
			panic(err)
		}
		if !exists {
			fmt.Printf("Create keypair for acraproxy and for acraserver that will be used in onekey test. Key %v not exists\n", key)
			os.Exit(1)
		}
	}
}
func GetPublicOneKey() *keys.PublicKey {
	public_key, err := utils.LoadPublicKey("src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey_server.pub")
	if err != nil {
		panic(err)
	}
	return public_key
}

func GenerateAcrastructRowsOneKey(public_key *keys.PublicKey, db *sql.DB) {
	for count := 0; count < config.ROW_COUNT; count++ {
		data, err := common.GenerateData()
		if err != nil {
			panic(err)
		}

		acrastruct, err := acrawriter.CreateAcrastruct(data, public_key, nil)
		if err != nil {
			panic(err)
		}
		_, err = db.Exec("INSERT INTO test_without_zone(data) VALUES ($1);", &acrastruct)
		if err != nil {
			panic(err)
		}
	}
}

func GenerateDataRows(db *sql.DB) {
	for count := 0; count < config.ROW_COUNT; count++ {
		data, err := common.GenerateData()
		if err != nil {
			panic(err)
		}
		_, err = db.Exec("INSERT INTO test_raw(data) VALUES ($1);", &data)
		if err != nil {
			panic(err)
		}
	}
}
