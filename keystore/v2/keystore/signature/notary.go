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

// Package signature implements generation and verification of signatures
// used by KeyStore to authenticate stored key data.
package signature

import (
	encodingASN1 "encoding/asn1"
	"errors"
	"time"

	"github.com/cossacklabs/acra/keystore/v2/keystore/asn1"
	log "github.com/sirupsen/logrus"
)

const serviceName = "keystore"
const notarySubsystemName = "notary"

// Errors produced by signature verification:
var (
	ErrNoAlgorithms   = errors.New("no key ring signing algorithms")
	ErrNoSignature    = errors.New("missing key ring signature")
	ErrSignatureError = errors.New("invalid key ring signature")
)

// Algorithm interface defines a particular signing algorithm for Notary.
// It signs and verifies raw byte data.
// Each algorithm is identified by an ASN.1 Object Identifier.
type Algorithm interface {
	AlgorithmOID() encodingASN1.ObjectIdentifier
	Sign(data, context []byte) []byte
	Verify(signature, data, context []byte) bool
}

// Notary cryptographically signs provided ASN.1 data.
type Notary struct {
	log        *log.Entry
	algorithms []Algorithm
}

// NewNotary makes a new notary with given encryptor.
func NewNotary(algorithms []Algorithm) (*Notary, error) {
	if len(algorithms) < 1 {
		return nil, ErrNoAlgorithms
	}
	return &Notary{
		log: log.WithFields(log.Fields{
			"service":   serviceName,
			"subsystem": notarySubsystemName,
		}),
		algorithms: algorithms,
	}, nil
}

// Sign provided container for given context. Updates signatures in the container
// and return serialized signed data.
func (s *Notary) Sign(container *asn1.SignedContainer, context []byte) ([]byte, error) {
	// ASN.1 does not store subsecond time precision. Update the timestamp
	// to match the value actually serialied.
	container.Payload.LastModified = container.Payload.LastModified.Truncate(time.Second)
	// Marshal the payload to get bytes that we sign
	payload, err := container.Payload.Marshal()
	if err != nil {
		s.log.WithError(err).Debug("failed to marshal payload for signing")
		return nil, err
	}
	// Now sign the entire thing and update signatures
	container.Signatures = s.signData(payload, context)
	// Finally, marshal the whole container with signatures. This could be done
	// more efficiently without remarshaling the payload, but...
	encoded, err := container.Marshal()
	if err != nil {
		s.log.WithError(err).Debug("failed to marshal signed data")
		return nil, err
	}
	return encoded, nil
}

// Verify signature on the data in given context. Parse and return the container
// wrapper. The caller should then parse container.Payload.Data based on the
// value of container.Payload.ContentType.
func (s *Notary) Verify(data, context []byte) (*asn1.VerifiedContainer, error) {
	// Unnmarshal top-level container wrapper
	decoded, err := asn1.UnmarshalVerifiedContainer(data)
	if err != nil {
		s.log.WithError(err).Debug("failed to unmarshal signed data")
		return nil, err
	}
	// Verify present signatures against the extracted payload data
	err = s.verifySignatures(decoded.Signatures, decoded.Payload.RawContent, context)
	if err != nil {
		s.log.WithError(err).Debug("failed to verify signature")
		return nil, err
	}
	return decoded, nil
}

func (s *Notary) signData(data, context []byte) []asn1.Signature {
	signatures := make([]asn1.Signature, len(s.algorithms))
	for i, algo := range s.algorithms {
		signatures[i].Algorithm = algo.AlgorithmOID()
		signatures[i].Signature = algo.Sign(data, context)
	}
	return signatures
}

func (s *Notary) verifySignatures(signatures []asn1.Signature, data, context []byte) error {
	// Quietly skip unknown algorithms for future compatibility, but we must
	// have at least one known algorithm and all known signatures should match.
	noSignaturesVerified := true
	for _, signature := range signatures {
		algorithm := s.algorithmWithOID(signature.Algorithm)
		if algorithm != nil {
			if !algorithm.Verify(signature.Signature, data, context) {
				return ErrSignatureError
			}
			noSignaturesVerified = false
		}
	}
	if noSignaturesVerified {
		return ErrNoSignature
	}
	return nil
}

func (s *Notary) algorithmWithOID(oid encodingASN1.ObjectIdentifier) Algorithm {
	for _, algo := range s.algorithms {
		if algo.AlgorithmOID().Equal(oid) {
			return algo
		}
	}
	return nil
}
