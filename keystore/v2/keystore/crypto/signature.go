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

package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	encodingASN1 "encoding/asn1"
	"hash"

	"github.com/cossacklabs/acra/keystore/v2/keystore/asn1"
)

// SignSha256 computes HMAC-SHA-256 signatures.
type SignSha256 struct {
	hmac hash.Hash
}

// NewSignSha256 makes a new HMAC-SHA-256 signature computer keyed by given key.
func NewSignSha256(key []byte) (*SignSha256, error) {
	return &SignSha256{hmac.New(sha256.New, key)}, nil
}

// AlgorithmOID returns ASN.1 OID for this algorithm.
func (s *SignSha256) AlgorithmOID() encodingASN1.ObjectIdentifier {
	return asn1.Sha256OID
}

// Sign provided data in given context.
func (s *SignSha256) Sign(data, context []byte) []byte {
	s.hmac.Reset()
	s.hmac.Write(context)
	s.hmac.Write(data)
	return s.hmac.Sum(nil)
}

// Verify that signature matches data in given context.
func (s *SignSha256) Verify(signature, data, context []byte) bool {
	expected := s.Sign(data, context)
	// Use constant-time comparison to mitigate side-channel attacks.
	return subtle.ConstantTimeCompare(expected, signature) == 1
}
