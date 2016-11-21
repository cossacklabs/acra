package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/acra/utils"
	"os"
)

func main() {
	poison_key_path := flag.String("poison_key", poison.DEFAULT_POISON_KEY_PATH, "path to file with poison key")
	acra_public_path := flag.String("acra_public", "", "path to acra public key to use")
	data_length := flag.Int("data_length", poison.DEFAULT_DATA_LENGTH, fmt.Sprintf("length of random data for data block in acrastruct. -1 is random in range 1..%v", poison.MAX_DATA_LENGTH))
	flag.Parse()
	if *acra_public_path == "" {
		fmt.Println("Error: missing acra public parameter")
		os.Exit(1)
	}
	acra_public_key, err := utils.LoadPublicKey(*acra_public_path)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("can't read acra public key", err))
		os.Exit(1)
	}

	*poison_key_path, err = utils.AbsPath(*poison_key_path)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("can't get absolute path to poison key", err))
		os.Exit(1)
	}

	poison_key, err := poison.GetOrCreatePoisonKey(*poison_key_path)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("can't create or read poison key", err))
		os.Exit(1)
	}
	poison_record, err := poison.CreatePoisonRecord(poison_key, *data_length, acra_public_key)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("can't create poison record", err))
	}
	fmt.Println(base64.StdEncoding.EncodeToString(poison_record))
}
