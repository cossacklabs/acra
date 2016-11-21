package acra

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	. "github.com/cossacklabs/acra/utils"
	"io/ioutil"
	"os"
	"os/user"
	"strings"
)

func addNewZone(output_dir string, fs_keystore bool) (string, error) {
	var output, dir string
	if len(output_dir) >= 2 && (output_dir)[:2] == "~/" {
		usr, err := user.Current()
		if err != nil {
			fmt.Println("Debug: %v\n", ErrorMessage("can't expand '~/'", err))
			return "", err
		}
		dir = usr.HomeDir
		output = strings.Replace(output_dir, "~", dir, 1)
	}
	if output_dir == "." {
		dir, err := os.Getwd()
		if err != nil {
			fmt.Printf("Debug: %v\n", ErrorMessage("can't expand current directory '.'", err))
			return "", err
		}
		output = dir
	}
	var key_store KeyStore
	if fs_keystore {
		key_store = NewFilesystemKeyStore(output)
	}
	id, public_key, err := key_store.GenerateKey()
	if err != nil {
		fmt.Printf("Debug: %v\n", ErrorMessage("can't add zone", err))
		return "", err
	}
	public_key_path := fmt.Sprintf("%s/%s", output, GetPublicKeyFilename(id))
	err = ioutil.WriteFile(public_key_path, public_key, 0644)
	if err != nil {
		fmt.Printf("Debug: %v\n", ErrorMessage(fmt.Sprintf("can't save public key at path: %s", public_key_path), err))
		return "", err
	}
	response := make(map[string]string)
	response["id"] = string(id)
	response["public_key"] = base64.StdEncoding.EncodeToString(public_key)
	json_output, err := json.Marshal(response)
	if err != nil {
		fmt.Printf("Debug: %v\n", ErrorMessage("can't encode to json", err))
		return "", err
	}
	return string(json_output), nil
}
