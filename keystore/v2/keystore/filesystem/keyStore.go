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
	"errors"
	"runtime"
	"time"

	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/asn1"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend"
	"github.com/cossacklabs/acra/keystore/v2/keystore/signature"
	log "github.com/sirupsen/logrus"
)

const serviceName = "keystore"

// KeyStore is a filesystem-like key store which keeps key rings in files.
//
// What exactly is the underlying filesystem is somewhat flexible and controlled by filesystem.Backend.
// Normally this is an actual filesystem but there are alternative implementations.
type KeyStore struct {
	encryptor crypto.KeyStoreSuite
	notary    *signature.Notary
	log       *log.Entry
	fs        backend.Backend
}

// OpenDirectory opens a read-only key store located in given directory.
func OpenDirectory(rootDir string, cryptosuite crypto.KeyStoreSuite) (api.KeyStore, error) {
	backend, err := backend.OpenDirectoryBackend(rootDir)
	if err != nil {
		return nil, err
	}
	return CustomKeyStore(backend, cryptosuite)
}

// OpenDirectoryRW opens a key store located in given directory.
// If the directory does not exist it will be created.
func OpenDirectoryRW(rootDir string, cryptosuite crypto.KeyStoreSuite) (api.MutableKeyStore, error) {
	backend, err := backend.CreateDirectoryBackend(rootDir)
	if err != nil {
		return nil, err
	}
	return CustomKeyStore(backend, cryptosuite)
}

// NewInMemory returns a new, empty in-memory key store.
// This is mostly useful for testing.
func NewInMemory(cryptosuite crypto.KeyStoreSuite) (api.MutableKeyStore, error) {
	return CustomKeyStore(backend.NewInMemory(), cryptosuite)
}

// CustomKeyStore returns a configurable filesystem-based key store.
// This constructor is useful if you want to provide a custom filesystem backend.
//
// The backend will be closed when this key store is closed,
// so a backend instance generally cannot be shared between key stores.
func CustomKeyStore(backend backend.Backend, cryptosuite crypto.KeyStoreSuite) (api.MutableKeyStore, error) {
	notary, err := signature.NewNotary(cryptosuite)
	if err != nil {
		return nil, err
	}
	keystore := &KeyStore{
		encryptor: cryptosuite,
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

//
// Encryption and signatures
//

func (s *KeyStore) keyStoreContext(context []byte) []byte {
	c := make([]byte, 0, len("AKSv2 keystore: ")+len(context))
	c = append(c, "AKSv2 keystore: "...)
	c = append(c, context...)
	return c
}

func (s *KeyStore) encrypt(data, context []byte) ([]byte, error) {
	return s.encryptor.Encrypt(data, s.keyStoreContext(context))
}

func (s *KeyStore) decrypt(data, context []byte) ([]byte, error) {
	return s.encryptor.Decrypt(data, s.keyStoreContext(context))
}

func (s *KeyStore) keyRingSignatureContext(path string) []byte {
	c := make([]byte, 0, len("key ring signature: ")+len(path))
	c = append(c, "key ring signature: "...)
	c = append(c, path...)
	return s.keyStoreContext(c)
}

// Errors returned by signature verification:
var (
	errIncorrectContentType = errors.New("KeyStore: incorrect ASN.1 ContentType")
	errUnsupportedVersion   = errors.New("KeyStore: unsupported ASN.1 Version")
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
	ringData := new(asn1.KeyRing)
	err = ringData.Unmarshal(verified.Payload.Data.FullBytes)
	if err != nil {
		log.WithError(err).Debug("failed to unmarshal key ring data")
	}
	log.WithField("last-modified", verified.Payload.LastModified).
		Trace("loaded key ring")
	return ringData, verified.Signatures, nil
}
