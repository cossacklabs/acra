/*
 * Copyright 2020, Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package filesystem

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"

	"github.com/go-redis/redis/v7"
	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/utils/args"

	keystoreV1 "github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/asn1"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend"
	"github.com/cossacklabs/acra/keystore/v2/keystore/signature"
)

const serviceName = "keystore"

// Errors returned by basic keystore.
var (
	ErrNotImplemented = errors.New("not implemented")
)

// KeyStore is a filesystem-like keystore which keeps key rings in files.
//
// What exactly is the underlying filesystem is somewhat flexible and controlled by filesystem.Backend.
// Normally this is an actual filesystem but there are alternative implementations.
type KeyStore struct {
	encryptor crypto.KeyEncryptor
	notary    *signature.Notary
	log       *log.Entry
	fs        backend.Backend
}

// OpenDirectory opens a read-only keystore located in given directory.
func OpenDirectory(rootDir string, cryptosuite *crypto.KeyStoreSuite) (api.KeyStore, error) {
	backend, err := backend.OpenDirectoryBackend(rootDir)
	if err != nil {
		return nil, err
	}
	return CustomKeyStore(backend, cryptosuite)
}

// OpenDirectoryRW opens a keystore located in given directory.
// If the directory does not exist it will be created.
func OpenDirectoryRW(rootDir string, cryptosuite *crypto.KeyStoreSuite) (api.MutableKeyStore, error) {
	backend, err := backend.CreateDirectoryBackend(rootDir)
	if err != nil {
		return nil, err
	}
	return CustomKeyStore(backend, cryptosuite)
}

// IsKeyDirectory checks if the directory contains a keystore version 2.
// This is a conservative check.
// That is, positive return value does not mean that the directory contains *a valid* keystore.
// However, false value means that the directory is definitely not a valid keystore.
// In particular, false is returned if the directory does not exists or cannot be opened.
func IsKeyDirectory(keyDirPath string, extractor *args.ServiceExtractor) bool {
	redisParams := cmd.ParseRedisCLIParametersFromFlags(extractor, "")
	if redisParams.KeysConfigured() {
		redisClient, err := backend.OpenRedisBackend(&backend.RedisConfig{
			RootDir: keyDirPath,
			Options: &redis.Options{
				Addr:     redisParams.HostPort,
				Password: redisParams.Password,
				DB:       redisParams.DBKeys,
			},
		})
		if err != nil {
			log.WithError(err).Debug("Failed to find keystore v2 in Redis")
			return false
		}
		// If the keystore has been opened successfully, it definitely exists.
		redisClient.Close()
		return true
	}
	// Otherwise, check the local filesystem storage provided by Acra CE.
	return backend.CheckDirectoryVersion(keyDirPath) == nil
}

// NewInMemory returns a new, empty in-memory keystore.
// This is mostly useful for testing.
func NewInMemory(cryptosuite *crypto.KeyStoreSuite) (api.MutableKeyStore, error) {
	return CustomKeyStore(backend.NewInMemory(), cryptosuite)
}

// CustomKeyStore returns a configurable filesystem-based keystore.
// This constructor is useful if you want to provide a custom filesystem backend.
//
// The backend will be closed when this keystore is closed,
// so a backend instance generally cannot be shared between keystores.
func CustomKeyStore(backend backend.Backend, cryptosuite *crypto.KeyStoreSuite) (api.MutableKeyStore, error) {
	notary, err := signature.NewNotary(cryptosuite.SignatureAlgorithms)
	if err != nil {
		return nil, err
	}
	keystore := &KeyStore{
		encryptor: cryptosuite.KeyEncryptor,
		notary:    notary,
		fs:        backend,
		log: log.WithFields(log.Fields{
			"service": serviceName,
		}),
	}
	runtime.SetFinalizer(keystore, (*KeyStore).finalize)
	return keystore, nil
}

func (s *KeyStore) finalize() {
	s.log.Warn("Close() has not been called for a KeyStore")
	err := s.Close()
	if err != nil {
		s.log.WithError(err).Warn("finalizer failed to close KeyStore")
	}
}

//
// KeyStore & MutableKeyStore interface
//

// Close this keystore, releasing associated resources.
func (s *KeyStore) Close() error {
	err := s.fs.Close()
	// Disarm finalizer since we have been closed manually.
	runtime.SetFinalizer(s, nil)
	return err
}

// OpenKeyRing opens an existing key ring at given path.
func (s *KeyStore) OpenKeyRing(path string) (api.KeyRing, error) {
	ring := newKeyRing(s, path)
	err := s.readKeyRing(ring)
	if err != nil {
		return nil, err
	}
	return ring, nil
}

// OpenKeyRingRW opens a modifiable key ring at given path.
func (s *KeyStore) OpenKeyRingRW(path string) (api.MutableKeyRing, error) {
	ring := newKeyRing(s, path)
	err := s.openKeyRing(ring)
	if err != nil {
		return nil, err
	}
	return ring, nil
}

// ListKeyRings enumerates all key rings present in this keystore.
func (s *KeyStore) ListKeyRings() (rings []string, err error) {
	err = s.fs.RLock()
	if err != nil {
		s.log.WithError(err).Debug("failed to lock store for reading")
		return nil, err
	}
	defer func() {
		err2 := s.fs.RUnlock()
		if err2 != nil {
			s.log.WithError(err2).Debug("failed to unlock store")
			if err == nil {
				err = err2
			}
		}
	}()

	rings, err = s.fs.ListAll()
	if err != nil {
		s.log.WithError(err).Debug("failed to list key rings")
		return nil, err
	}
	for i := range rings {
		rings[i] = strings.TrimSuffix(rings[i], keyringSuffix)
	}
	return rings, nil
}

// DescribeKeyRing describes key ring by its purpose path.
func (s *KeyStore) DescribeKeyRing(path string) (*keystoreV1.KeyDescription, error) {
	// This is basic keystore which does not define any particular key rings.
	// This method will be overridden by actual keystore implementation.
	return nil, ErrNotImplemented
}

// DescribeRotatedKeyRing return KeyDescription list of rotated keys
func (s *KeyStore) DescribeRotatedKeyRing(path string) ([]keystoreV1.KeyDescription, error) {
	// This is basic keystore which does not define any particular key rings.
	// This method will be overridden by actual keystore implementation.
	return nil, ErrNotImplemented
}

// ExportKeyRings packages specified key rings for export.
// Key ring data is encrypted and signed using given cryptosuite.
// Resulting container can be imported into existing or different keystore with ImportKeyRings().
func (s *KeyStore) ExportKeyRings(paths []string, cryptosuite *crypto.KeyStoreSuite, mode keystoreV1.ExportMode) ([]byte, error) {
	keyRings, err := s.exportKeyRings(paths, mode)
	if err != nil {
		return nil, err
	}
	defer zeroizeKeyRings(keyRings)
	return s.encryptAndSignKeyRings(keyRings, cryptosuite)
}

// ImportKeyRings unpacks key rings packaged by ExportKeyRings.
// The provided cryptosuite is used to verify the signature on the container and decrypt key ring data.
// Optional delegate can be used to control various aspects of the import process, such as conflict resolution.
// Returns a list of processed key rings.
func (s *KeyStore) ImportKeyRings(exportData []byte, cryptosuite *crypto.KeyStoreSuite, delegate api.KeyRingImportDelegate) ([]string, error) {
	if delegate == nil {
		delegate = &defaultImportDelegate{}
	}

	keyRings, err := s.decryptAndVerifyKeyRings(exportData, cryptosuite)
	if err != nil {
		return nil, err
	}
	defer zeroizeKeyRings(keyRings)

	keyRingIDs := make([]string, len(keyRings))
	for i := range keyRings {
		err := s.importKeyRing(&keyRings[i], delegate)
		if err != nil {
			return nil, err
		}
		keyRingIDs[i] = string(keyRings[i].Purpose)
	}

	return keyRingIDs, nil
}

type defaultImportDelegate struct{}

func (*defaultImportDelegate) DecideKeyRingOverwrite(currentData, newData *asn1.KeyRing) (api.ImportDecision, error) {
	return api.ImportAbort, ErrKeyRingExists
}

//
// Encryption and signatures
//

func (s *KeyStore) keyStoreContext(context []byte) []byte {
	c := make([]byte, 0, len("AKSv2 keystore: ")+len(context))
	c = append(c, "AKSv2 keystore: "...)
	c = append(c, context...)
	return c
}

func (s *KeyStore) encrypt(data, ctx []byte) ([]byte, error) {
	keyContext := keystoreV1.NewEmptyKeyContext(s.keyStoreContext(ctx))
	return s.encryptor.Encrypt(context.Background(), data, keyContext)
}

func (s *KeyStore) decrypt(data, ctx []byte) ([]byte, error) {
	keyContext := keystoreV1.NewEmptyKeyContext(s.keyStoreContext(ctx))
	return s.encryptor.Decrypt(context.Background(), data, keyContext)
}

func (s *KeyStore) keyRingSignatureContext(path string) []byte {
	c := make([]byte, 0, len("key ring signature: ")+len(path))
	c = append(c, "key ring signature: "...)
	c = append(c, path...)
	return s.keyStoreContext(c)
}

// Errors returned by signature verification:
var (
	errIncorrectContentType = errors.New("incorrect ASN.1 ContentType")
	errUnsupportedVersion   = errors.New("unsupported ASN.1 Version")
)

func (s *KeyStore) signKeyRing(ring *asn1.KeyRing, path string) ([]byte, []asn1.Signature, error) {
	container := asn1.SignedContainer{Payload: asn1.SignedPayload{
		ContentType:  asn1.TypeKeyRing,
		Version:      asn1.KeyRingVersion2,
		LastModified: time.Now(),
		Data:         *ring,
	}}
	context := s.keyRingSignatureContext(path)
	signedData, err := s.notary.Sign(&container, context)
	if err != nil {
		s.log.WithError(err).Warn("failed to sign key ring data")
		return nil, nil, err
	}
	return signedData, container.Signatures, nil
}

func (s *KeyStore) verifyKeyRing(data []byte, path string) (*asn1.KeyRing, []asn1.Signature, error) {
	log := s.log.WithField("path", path)
	context := s.keyRingSignatureContext(path)
	verified, err := s.notary.Verify(data, context)
	if err != nil {
		log.WithError(err).Warn("failed to verify key ring data")
		return nil, nil, err
	}
	if verified.Payload.ContentType != asn1.TypeKeyRing {
		log.WithField("actual", verified.Payload.ContentType).WithField("expected", asn1.TypeKeyRing).
			Debug("incorrect key ring ContentType")
		return nil, nil, errIncorrectContentType
	}
	if verified.Payload.Version != asn1.KeyRingVersion2 {
		log.WithField("actual", verified.Payload.Version).WithField("expected", asn1.KeyRingVersion2).
			Debug("unsupported key ring Version")
		return nil, nil, errUnsupportedVersion
	}
	ringData, err := asn1.UnmarshalKeyRing(verified.Payload.Data.FullBytes)
	if err != nil {
		log.WithError(err).Debug("failed to unmarshal key ring data")
	}
	log.WithField("last-modified", verified.Payload.LastModified).
		Trace("loaded key ring")
	return ringData, verified.Signatures, nil
}
