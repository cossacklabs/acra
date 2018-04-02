// Copyright 2018, Cossack Labs Limited
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
	"errors"
	"flag"
	log "github.com/sirupsen/logrus"
	"os"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/themis/gothemis/cell"
	"io/ioutil"
	"strings"
	"fmt"
	"github.com/cossacklabs/acra/keystore"
)

type HashedPasswords map[string]string

const (
	PasswordSeparator = ":"
	LineSeparator     = "\n"
)

func (hp HashedPasswords) Bytes() (passwordBytes []byte) {
	passwordBytes = []byte{}
	for name, hash := range hp {
		passwordBytes = append(passwordBytes, []byte(name+PasswordSeparator+hash+LineSeparator)...)
	}
	return passwordBytes
}

func (hp HashedPasswords) WriteToFile(file string, keystore *keystore.FilesystemKeyStore) error {
	key, err := keystore.GetAuthKey(false)
	if err != nil {
		return err
	}
	SecureCell := cell.New(key, cell.CELL_MODE_SEAL)
	crypted, _, err := SecureCell.Protect(hp.Bytes(), nil)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, crypted, 0644)
}

func (hp HashedPasswords) SetPassword(name, password string) (err error) {
	if len(password) == 0 {
		return errors.New("passwords is empty")
	}
	salt := cmd.RandomStringBytes(16)
	argon2Params := cmd.InitArgon2Params()
	hashBytes, err := cmd.HashArgon2(password, salt, argon2Params)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	a := cmd.UserAuth{Salt: salt, Hash: hashBytes, Argon2Params: argon2Params}
	hp[name] = a.UserAuthString(":", ",")
	return nil
}

func ParseHtpasswdFile(file string, keystore *keystore.FilesystemKeyStore) (passwords HashedPasswords, err error) {
	htpasswdBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}
	key, err := keystore.GetAuthKey(false)
	if err != nil {
		return
	}
	SecureCell := cell.New(key, cell.CELL_MODE_SEAL)
	authData, err := SecureCell.Unprotect(htpasswdBytes, nil, nil)
	if err != nil {
		return
	}
	return ParseHtpasswd(authData)
}

func ParseHtpasswd(htpasswdBytes []byte) (passwords HashedPasswords, err error) {
	authFieldsCount := 4
	lines := strings.Split(string(htpasswdBytes), LineSeparator)
	passwords = make(map[string]string)
	for index, line := range lines {
		line = strings.Trim(line, " ")
		if len(line) == 0 {
			continue
		}
		parts := strings.Split(line, PasswordSeparator)
		if len(parts) != authFieldsCount {
			err = errors.New(fmt.Sprintf("wrong line no. %d, unexpected number (%v) of splitted parts split by %v", index+1, len(parts), PasswordSeparator))
			return
		}
		for i, part := range parts {
			parts[i] = strings.Trim(part, " ")
		}
		_, alreadyExists := passwords[parts[0]]
		if alreadyExists {
			err = errors.New(fmt.Sprintf("wrong line no. %d, user (%v) already defined", index, parts[0]))
			return
		}
		passwords[parts[0]] = strings.Join(parts[1:authFieldsCount], PasswordSeparator)
	}
	return
}

func RemoveUser(file, user string, keystore *keystore.FilesystemKeyStore) error {
	passwords, err := ParseHtpasswdFile(file, keystore)
	if err != nil {
		return err
	}
	_, ok := passwords[user]
	if !ok {
		return errors.New("user not found in file")
	}
	delete(passwords, user)
	return passwords.WriteToFile(file, keystore)
}

func SetPassword(file, name, password string, keystore *keystore.FilesystemKeyStore) error {
	_, err := os.Stat(file)
	passwords := HashedPasswords(map[string]string{})
	if err == nil {
		passwords, err = ParseHtpasswdFile(file, keystore)
		if err != nil {
			return err
		}
	}
	err = passwords.SetPassword(name, password)
	if err != nil {
		return err
	}
	return passwords.WriteToFile(file, keystore)
}

func main() {
	set := flag.Bool("set", false, "Add/update password for user")
	remove := flag.Bool("remove", false, "Remove user")
	user := flag.String("user", "", "User")
	pwd := flag.String("pwd", "", "Password")
	filePath := flag.String("file", cmd.DEFAULT_ACRA_AUTH_PATH, "Auth file")
	keysDir := flag.String("keys_dir", keystore.DEFAULT_KEY_DIR_SHORT, "Folder from which will be loaded keys")
	flag.Parse()
	flags := []*bool{set, remove}
	logging.SetLogLevel(logging.LOG_VERBOSE)

	keyStore, err := keystore.NewFilesystemKeyStore(*keysDir)
	if err != nil {
		log.WithError(err).Errorln("NewFilesystemKeyStore")
		os.Exit(1)
	}

	n := 0
	for _, o := range flags {
		if *o {
			n += 1
			if n > 1 {
				log.Errorln("Too many options, use one of --set or --remove")
				os.Exit(1)
			}
		}
	}

	if *user == "" {
		log.Errorln("Empty user name/login")
		flag.Usage()
		os.Exit(1)
	}

	if *set {
		if *pwd == "" {
			log.Errorln("Empty password")
			flag.Usage()
			os.Exit(1)
		}
		err := SetPassword(*filePath, *user, *pwd, keyStore)
		if err != nil {
			log.WithError(err).Errorln("SetPassword")
			os.Exit(1)
		}
	}
	if *remove {
		err := RemoveUser(*filePath, *user, keyStore)
		if err != nil {
			log.WithError(err).Errorln("RemoveUser")
			os.Exit(1)
		}
	}

}
