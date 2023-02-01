package keystore

import (
	log "github.com/sirupsen/logrus"

	keystoreV1 "github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
)

// KeyBackuper implements keystore.Exporter and keystore.Importer interface for v2
type KeyBackuper struct {
	storage       api.BackupKeystore
	privateFolder string
	publicFolder  string
}

// NewKeyBackuper create, initialize and return new instance of KeyBackuper
func NewKeyBackuper(privateFolder, publicFolder string, storage api.BackupKeystore) (*KeyBackuper, error) {
	if publicFolder == "" {
		publicFolder = privateFolder
	}
	return &KeyBackuper{privateFolder: privateFolder, publicFolder: publicFolder, storage: storage}, nil
}

// Export keys from KeyStore encrypted with new key for backup
func (store *KeyBackuper) Export(exportIDs []keystoreV1.ExportID, mode keystoreV1.ExportMode) (*keystoreV1.KeysBackup, error) {
	var exportPaths []string
	if mode == keystoreV1.ExportAllKeys {
		var err error
		exportPaths, err = store.storage.ListKeyRings()
		if err != nil {
			log.WithError(err).Fatal("Failed to list available keys")
		}
	}

	if len(exportIDs) != 0 {
		for _, exportID := range exportIDs {
			switch exportID.KeyKind {
			case keystoreV1.KeyPoisonPublic, keystoreV1.KeyPoisonPrivate:
				exportPaths = append(exportPaths, "poison-record")
			case keystoreV1.KeyPoisonSymmetric:
				exportPaths = append(exportPaths, "poison-record-sym")
			case keystoreV1.KeyStoragePrivate, keystoreV1.KeyStoragePublic:
				exportPaths = append(exportPaths, "client/"+string(exportID.ContextID)+"/storage")
			case keystoreV1.KeySymmetric:
				exportPaths = append(exportPaths, "client/"+string(exportID.ContextID)+"/storage-sym")
			case keystoreV1.KeySearch:
				exportPaths = append(exportPaths, "client/"+string(exportID.ContextID)+"/hmac-sym")
			case keystoreV1.KeyPath:
				// if KeyKind is KeyPath, added ContextID as path
				exportPaths = append(exportPaths, string(exportID.ContextID))
			}
		}
	}

	encryptionKeyData, cryptosuite, err := prepareExportEncryptionKeys()
	if err != nil {
		log.WithError(err).Errorln("Failed to prepare encryption keys")
		return nil, err
	}

	exportedData, err := store.storage.ExportKeyRings(exportPaths, cryptosuite, mode)
	if err != nil {
		log.WithError(err).Debug("Failed to export key rings")
		return nil, err
	}

	return &keystoreV1.KeysBackup{
		Keys: encryptionKeyData,
		Data: exportedData,
	}, nil
}

// Import keys from backup to current keystore
func (store *KeyBackuper) Import(backup *keystoreV1.KeysBackup) ([]keystoreV1.KeyDescription, error) {
	importEncryptionKeys := &SerializedKeys{}
	err := importEncryptionKeys.Unmarshal(backup.Keys)
	if err != nil {
		log.WithError(err).Debug("Failed to parse key file content")
		return nil, err
	}

	cryptosuite, err := crypto.NewSCellSuite(importEncryptionKeys.Encryption, importEncryptionKeys.Signature)
	if err != nil {
		log.WithError(err).Debug("Failed to initialize cryptosuite")
		return nil, err
	}

	keyIDs, err := store.storage.ImportKeyRings(backup.Data, cryptosuite, nil)
	if err != nil {
		log.WithError(err).Debug("Failed to import key rings")
		return nil, err
	}
	descriptions, err := DescribeKeyRings(keyIDs, store.storage)
	if err != nil {
		log.WithError(err).Debug("Failed to describe imported key rings")
		return nil, err
	}

	return descriptions, nil
}

// prepareExportEncryptionKeys generates new ephemeral keys for key export operation.
func prepareExportEncryptionKeys() ([]byte, *crypto.KeyStoreSuite, error) {
	keys, err := NewMasterKeys()
	if err != nil {
		log.WithError(err).Debug("Failed to generate master keys")
		return nil, nil, err
	}

	serializedKeys, err := keys.Marshal()
	if err != nil {
		log.WithError(err).Debug("Failed to serialize keys in JSON")
		return nil, nil, err
	}

	// We do not zeroize the keys since a) they are stored by reference in the cryptosuite,
	// b) they have not been used to encrypt anything yet.
	cryptosuite, err := crypto.NewSCellSuite(keys.Encryption, keys.Signature)
	if err != nil {
		log.WithError(err).Debug("Failed to setup cryptosuite")
		return nil, nil, err
	}

	return serializedKeys, cryptosuite, nil
}
