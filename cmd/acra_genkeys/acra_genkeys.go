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
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/themis/gothemis/keys"
	"os"
	"os/user"
	"strings"
)

func absPath(path string) (string, error) {
	if path[:2] == "~/" {
		usr, err := user.Current()
		if err != nil {
			return path, err
		}
		dir := usr.HomeDir
		path = strings.Replace(path, "~", dir, 1)
		return path, nil
	}
	return path, nil
}

func main() {
	key_name := flag.String("key_name", "client", "filename keys")
	output_dir := flag.String("output", keystore.DEFAULT_KEY_DIR_SHORT, "output dir")
	flag.Parse()

	keypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		panic(err)
	}

	*output_dir, err = absPath(*output_dir)
	if err != nil {
		panic(err)
	}

	err = os.MkdirAll(*output_dir, 0700)
	if err != nil {
		panic(err)
	}

	file, err := os.OpenFile(fmt.Sprintf("%v/%v", *output_dir, *key_name), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
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

	file, err = os.OpenFile(fmt.Sprintf("%v/%v.pub", *output_dir, *key_name), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
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
