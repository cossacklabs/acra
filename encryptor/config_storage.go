package encryptor

import "github.com/cossacklabs/acra/keystore/filesystem"

// ConfigStorage describe main Storage interface for loading encryptor config from different sources
type ConfigStorage interface {
	filesystem.Storage
	GetEncryptorConfigPath() string
}
