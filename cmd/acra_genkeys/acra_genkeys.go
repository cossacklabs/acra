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
	"flag"
	"fmt"
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"os"
)

var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName("acra_genkeys")

func create_keys(filename, output_dir string) {
	keypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		panic(err)
	}
	if output_dir[len(output_dir)-1] != '/' {
		output_dir = output_dir + "/"
	}
	file, err := os.OpenFile(fmt.Sprintf("%v%v", output_dir, filename), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}

	n, err := file.Write(keypair.Private.Value)
	if n != len(keypair.Private.Value) {
		panic("Error in writing private key")
	}
	if err != nil {
		panic(err)
	}
	fmt.Println(file.Name())

	file, err = os.OpenFile(fmt.Sprintf("%v%v.pub", output_dir, filename), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}

	n, err = file.Write(keypair.Public.Value)
	if n != len(keypair.Public.Value) {
		panic("Error in writing public key")
	}
	if err != nil {
		panic(err)
	}
	fmt.Println(file.Name())
}

func main() {
	client_id := flag.String("client_id", "client", "Client id")
	acraproxy := flag.Bool("acraproxy", false, "Create keypair only for acraproxy")
	acraserver := flag.Bool("acraserver", false, "Create keypair only for acraserver")
	data_keys := flag.Bool("storage", false, "Create keypair for data encryption/decryption")
	output_dir := flag.String("output", keystore.DEFAULT_KEY_DIR_SHORT, "Folder where will be saved keys")

	err := cmd.Parse(DEFAULT_CONFIG_PATH)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("Can't parse args", err))
		os.Exit(1)
	}

	store, err := keystore.NewFilesystemKeyStore(*output_dir)
	if err != nil {
		panic(err)
	}

	if *acraproxy {
		err = store.GenerateProxyKeys([]byte(*client_id))
		if err != nil {
			panic(err)
		}
	} else if *acraserver {
		err = store.GenerateServerKeys([]byte(*client_id))
		if err != nil {
			panic(err)
		}
	} else if *data_keys {
		err = store.GenerateDataEncryptionKeys([]byte(*client_id))
		if err != nil {
			panic(err)
		}
	} else {
		err = store.GenerateProxyKeys([]byte(*client_id))
		if err != nil {
			panic(err)
		}

		err = store.GenerateServerKeys([]byte(*client_id))
		if err != nil {
			panic(err)
		}

		err = store.GenerateDataEncryptionKeys([]byte(*client_id))
		if err != nil {
			panic(err)
		}
	}
}
