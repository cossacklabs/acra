package main

import (
	"github.com/cossacklabs/acra"
	. "github.com/cossacklabs/acra/utils"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strings"
)

func main() {
	output_dir := flag.String("output_dir", "~/.ssession", "output dir to save public key")
	fs_keystore := flag.Bool("fs", true, "use filesystem key store")
	//verbose := flag.Bool("v", false, "log to stdout")
	flag.Parse()
	//if *verbose{
	//	log.SetOutput(os.Stdout)
	//}
	var output, dir string
	if len(*output_dir) >= 2 && (*output_dir)[:2] == "~/" {
		usr, err := user.Current()
		if err != nil {
			fmt.Printf("Error: %v\n", ErrorMessage("can't expand '~/'", err))
			os.Exit(1)
		}
		dir = usr.HomeDir
		output = strings.Replace(*output_dir, "~", dir, 1)
	}
	if *output_dir == "." {
		dir, err := os.Getwd()
		if err != nil {
			fmt.Printf("Error: %v\n", ErrorMessage("can't expand current directory '.'", err))
			os.Exit(1)
		}
		output = dir
	}
	var key_store acra.KeyStore
	if *fs_keystore {
		key_store = acra.NewFilesystemKeyStore(output)
	}
	id, public_key, err := key_store.GenerateKey()
	if err != nil {
		fmt.Printf("Error: %v\n", ErrorMessage("can't add zone", err))
		os.Exit(1)
	}
	public_key_path := fmt.Sprintf("%s/%s", output, acra.GetPublicKeyFilename(id))
	err = ioutil.WriteFile(public_key_path, public_key, 0644)
	if err != nil {
		fmt.Printf("Error: can't save public key at path: %s\n", public_key_path)
		os.Exit(1)
	}
	response := make(map[string]string)
	response["id"] = string(id)
	response["public_key"] = base64.StdEncoding.EncodeToString(public_key)
	json_output, err := json.Marshal(response)
	if err != nil {
		fmt.Printf("Error: %v\n", ErrorMessage("can't encode to json", err))
		os.Exit(1)
	}
	fmt.Println(string(json_output))
}
