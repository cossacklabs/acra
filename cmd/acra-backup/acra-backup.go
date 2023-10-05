/*
Copyright 2020, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"

	log "github.com/sirupsen/logrus"
)

// BackupMasterKeyVarName env variable name, used as back MASTER_KEY
const BackupMasterKeyVarName = "BACKUP_MASTER_KEY"

const (
	actionExport = "export"
	actionImport = "import"
)

// Constants handy for AcraTranslator.
const (
	ServiceName = "acra-backup"
)

// DefaultConfigPath relative path to config which will be parsed as default
var DefaultConfigPath = utils.GetConfigPathByName(ServiceName)

func main() {
	log.Warn("acra-backup tool is DEPRECATED since 0.96.0 and will be removed in 0.97.0. Use acra-keys instead.")
	loggingFormat := flag.String("logging_format", "plaintext", "Logging format: plaintext, json or CEF")
	outputDir := flag.String("keys_private_dir", keystore.DefaultKeyDirShort, "Folder with private keys")
	outputPublicKey := flag.String("keys_public_dir", "", "Folder with public keys. Leave empty if keys stored in same folder as keys_private_dir")
	action := flag.String("action", "", fmt.Sprintf("%s|%s values are accepted", actionImport, actionExport))
	file := flag.String("file", "", fmt.Sprintf("path to file which will be used for %s|%s action", actionImport, actionExport))

	network.RegisterTLSBaseArgs(flag.CommandLine)
	cmd.RegisterRedisKeystoreParameters()
	keyloader.RegisterKeyStoreStrategyParameters()

	err := cmd.Parse(DefaultConfigPath, ServiceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}
	formatter := logging.CreateFormatter(*loggingFormat)
	formatter.SetServiceName(ServiceName)
	log.SetOutput(os.Stderr)

	log.WithField("version", utils.VERSION).Infof("Starting service %v [pid=%v]", ServiceName, os.Getpid())
	var storage filesystem.Storage
	if redis := cmd.ParseRedisCLIParameters(); redis.KeysConfigured() {
		storage, err = filesystem.NewRedisStorage(redis.HostPort, redis.Password, redis.DBKeys, nil)
		if err != nil {
			log.WithError(err).Errorln("Can't initialize redis storage")
			os.Exit(1)
		}
	} else {
		storage = &filesystem.DummyStorage{}
	}

	keyStoreEncryptor, err := keyloader.CreateKeyEncryptor(flag.CommandLine, "")
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore KeyEncryptor")
		os.Exit(1)
	}

	backuper, err := filesystem.NewKeyBackuper(*outputDir, *outputPublicKey, storage, keyStoreEncryptor, nil)
	if err != nil {
		log.WithError(err).Errorln("Can't initialize backuper")
		os.Exit(1)
	}
	switch *action {
	case actionImport:
		b64value := os.Getenv(BackupMasterKeyVarName)
		if len(b64value) == 0 {
			log.Errorf("Env variable %s is empty", BackupMasterKeyVarName)
			os.Exit(1)
		}
		key, err := base64.StdEncoding.DecodeString(b64value)
		if err != nil {
			log.WithError(err).Errorf("Can't parse base64 value from env variable %s", BackupMasterKeyVarName)
			os.Exit(1)
		}
		if err = keystore.ValidateMasterKey(key); err != nil {
			log.WithError(err).Errorf("Symmetric key stored in %s env variable is invalid", BackupMasterKeyVarName)
			os.Exit(1)
		}

		keysContent, err := os.ReadFile(*file)
		if err != nil {
			log.WithError(err).Errorln("Can't read file with exported keys")
			os.Exit(1)
		}
		backup := keystore.KeysBackup{Keys: key, Data: keysContent}
		if _, err := backuper.Import(&backup); err != nil {
			log.WithError(err).Errorln("Can't import keys")
			os.Exit(1)
		}
	case actionExport:
		backup, err := backuper.Export(nil, keystore.ExportAllKeys)
		if err != nil {
			log.WithError(err).Errorln("Can't generate backup")
			os.Exit(1)
		}
		base64MasterKey := base64.StdEncoding.EncodeToString(backup.Keys)
		utils.ZeroizeSymmetricKey(backup.Keys)
		if err := os.WriteFile(*file, backup.Keys, filesystem.PrivateFileMode); err != nil {
			log.WithError(err).Errorf("Can't write backup to file %s", *file)
			os.Exit(1)
		}
		log.Infof("Backup master key: %s\n Backup saved to file: %s", base64MasterKey, *file)
	default:
		log.Errorln("Invalid value for --action parameter")
		os.Exit(1)
	}
}
