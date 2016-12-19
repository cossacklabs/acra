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
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/acra/utils"
	"github.com/vharitonsky/iniflags"
	"os"
)

var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName("acra_genpoisonrecord")

func main() {
	poison_key_path := flag.String("poison_key", poison.DEFAULT_POISON_KEY_PATH, "path to file with poison key")
	acra_public_path := flag.String("acra_public", "", "path to acra public key to use")
	data_length := flag.Int("data_length", poison.DEFAULT_DATA_LENGTH, fmt.Sprintf("length of random data for data block in acrastruct. -1 is random in range 1..%v", poison.MAX_DATA_LENGTH))

	utils.LoadFromConfig(DEFAULT_CONFIG_PATH)
	iniflags.Parse()

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
