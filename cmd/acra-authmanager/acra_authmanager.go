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
	"fmt"
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/cell"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"strings"
)

// HashedPasswords stores username:hashed_password map
type HashedPasswords map[string]string

// Constants used by AcraAuthmanager
var (
	DEFAULT_CONFIG_PATH = utils.GetConfigPathByName("acra-authmanager")
	SERVICE_NAME        = "acra-authmanager"
)

// Constants used for Argon password manager
const (
	AuthFieldSeparator       = ":"
	AuthArgon2ParamSeparator = ","
	LineSeparator            = "\n"
	SaltLength               = 16
	AuthFieldCount           = 4
	Space                    = " "
)

// Bytes returns user name and password hash
func (hp HashedPasswords) Bytes() (passwordBytes []byte) {
	passwordBytes = []byte{}
	for name, hash := range hp {
		passwordBytes = append(passwordBytes, []byte(name+AuthFieldSeparator+hash+LineSeparator)...)
	}
	return passwordBytes
}

// WriteToFile writes encrypted names and password hashes to file
func (hp HashedPasswords) WriteToFile(file string, keystore *filesystem.FilesystemKeyStore) error {
	key, err := keystore.GetAuthKey(false)
	if err != nil {
		return err
	}
	SecureCell := cell.New(key, cell.CELL_MODE_SEAL)
	crypted, _, err := SecureCell.Protect(hp.Bytes(), nil)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, crypted, 0600)
}

// SetPassword sets hashed password to user name
func (hp HashedPasswords) SetPassword(name, password string) (err error) {
	if len(password) == 0 {
		return errors.New("passwords is empty")
	}
	salt := cmd.RandomStringBytes(SaltLength)
	argon2Params := cmd.InitArgon2Params()
	hashBytes, err := cmd.HashArgon2(password, salt, argon2Params)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	a := cmd.UserAuth{Salt: salt, Hash: hashBytes, Argon2Params: argon2Params}
	hp[name] = a.UserAuthString(AuthFieldSeparator, AuthArgon2ParamSeparator)
	return nil
}

func parseHtpasswdFile(file string, keystore *filesystem.FilesystemKeyStore) (passwords HashedPasswords, err error) {
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
	return parseHtpasswd(authData)
}

func parseHtpasswd(htpasswdBytes []byte) (passwords HashedPasswords, err error) {
	lines := strings.Split(string(htpasswdBytes), LineSeparator)
	passwords = make(map[string]string)
	for index, line := range lines {
		line = strings.Trim(line, Space)
		if len(line) == 0 {
			continue
		}
		parts := strings.Split(line, AuthFieldSeparator)
		if len(parts) != AuthFieldCount {
			err = errors.New(fmt.Sprintf("wrong line no. %d, unexpected number (%v) of splitted parts split by %v", index+1, len(parts), AuthFieldSeparator))
			return
		}
		for i, part := range parts {
			parts[i] = strings.Trim(part, Space)
		}
		_, alreadyExists := passwords[parts[0]]
		if alreadyExists {
			err = errors.New(fmt.Sprintf("wrong line no. %d, user (%v) already defined", index, parts[0]))
			return
		}
		passwords[parts[0]] = strings.Join(parts[1:AuthFieldCount], AuthFieldSeparator)
	}
	return
}

func removeUser(file, user string, keystore *filesystem.FilesystemKeyStore) error {
	passwords, err := parseHtpasswdFile(file, keystore)
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

func setPassword(file, name, password string, keystore *filesystem.FilesystemKeyStore) error {
	_, err := os.Stat(file)
	passwords := HashedPasswords(map[string]string{})
	if err == nil {
		passwords, err = parseHtpasswdFile(file, keystore)
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
	password := flag.String("password", "", "Password")
	filePath := flag.String("file", cmd.DEFAULT_ACRA_AUTH_PATH, "Auth file")
	keysDir := flag.String("keys_dir", keystore.DEFAULT_KEY_DIR_SHORT, "Folder from which will be loaded keys")
	debug := flag.Bool("d", false, "Turn on debug logging")

	if err := cmd.Parse(DEFAULT_CONFIG_PATH, SERVICE_NAME); err != nil {
		log.WithError(err).Errorln("can't parse cmd arguments")
		os.Exit(1)
	}

	flags := []*bool{set, remove}

	if *debug {
		logging.SetLogLevel(logging.LOG_DEBUG)
	} else {
		logging.SetLogLevel(logging.LOG_VERBOSE)
	}

	masterKey, err := keystore.GetMasterKeyFromEnvironment()
	if err != nil {
		log.WithError(err).Errorln("can't load master key")
		os.Exit(1)
	}
	encryptor, err := keystore.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithError(err).Errorln("can't initialize scell encryptor")
		os.Exit(1)
	}
	keyStore, err := filesystem.NewFilesystemKeyStore(*keysDir, encryptor)
	if err != nil {
		log.WithError(err).Errorln("NewFilesystemKeyStore")
		os.Exit(1)
	}

	n := 0
	for _, o := range flags {
		if *o {
			n++
			if n > 1 {
				log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongParam).Errorln("Too many options, use one of --set or --remove")
				os.Exit(1)
			}
		}
	}

	if *user == "" {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongParam).Errorln("Empty user name/login")
		flag.Usage()
		os.Exit(1)
	}

	if *set {
		if *password == "" {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorWrongParam).Errorln("Empty password")
			flag.Usage()
			os.Exit(1)
		}
		err := setPassword(*filePath, *user, *password, keyStore)
		if err != nil {
			log.WithError(err).Errorln("SetPassword failed")
			os.Exit(1)
		}
	}
	if *remove {
		err := removeUser(*filePath, *user, keyStore)
		if err != nil {
			log.WithError(err).Errorln("RemoveUser failed")
			os.Exit(1)
		}
	}

}
