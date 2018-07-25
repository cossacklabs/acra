package common

import (
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
)

// TranslatorData connects KeyStorage and Poison records settings for HTTP and gRPC decryptors.
type TranslatorData struct {
	Keystorage            keystore.KeyStore
	PoisonRecordCallbacks *base.PoisonCallbackStorage
	CheckPoisonRecords    bool
}
