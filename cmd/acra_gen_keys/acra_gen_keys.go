package main

import (
	"flag"
	"fmt"
	"github.com/cossacklabs/themis/gothemis/keys"
	"os"
	"os/user"
	"strings"
	"github.com/cossacklabs/acra/keystore"
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

	file, err := os.Create(fmt.Sprintf("%v/%v", *output_dir, *key_name))
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

	file, err = os.Create(fmt.Sprintf("%v/%v.pub", *output_dir, *key_name))
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
