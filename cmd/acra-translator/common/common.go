package common

import (
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
)

type TranslatorData struct {
	Keystorage            keystore.KeyStore
	PoisonRecordCallbacks *base.PoisonCallbackStorage
	CheckPoisonRecords    bool
}
