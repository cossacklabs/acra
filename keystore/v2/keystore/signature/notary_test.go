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

package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	encodingASN1 "encoding/asn1"
	"hash"
	"testing"
	"time"

	"github.com/cossacklabs/acra/keystore/v2/keystore/asn1"
)

var (
	masterKey = []byte("the secret key")
	context   = []byte("signing context")
)

const exampleContentType = asn1.ContentType(42)
const exampleContentVersion = 1

type examplePayload struct {
	Value1 int
	Value2 int
}

type testKeyedHmac struct{}

func (*testKeyedHmac) HmacSha256() hash.Hash {
	return hmac.New(sha256.New, masterKey)
}

func TestValidSignature(t *testing.T) {
	now := time.Now()
	container := asn1.SignedContainer{Payload: asn1.SignedPayload{
		ContentType:  exampleContentType,
		Version:      exampleContentVersion,
		LastModified: now,
		Data: examplePayload{
			Value1: 0xADEAD,
			Value2: 0xBEE,
		},
	}}

	s, err := NewNotary(new(testKeyedHmac))
	if err != nil {
		t.Fatalf("newNotary() failed: %v", err)
	}

	signed, err := s.Sign(&container, context)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	if len(container.Signatures) != 1 {
		t.Errorf("invalid signature count")
	} else {
		if !container.Signatures[0].Algorithm.Equal(asn1.Sha256OID) {
			t.Errorf("invalid signature algorithm")
		}
	}

	verified, err := s.Verify(signed, context)
	if err != nil {
		t.Fatalf("failed to verify data: %v", err)
	}

	if verified.Payload.ContentType != exampleContentType {
		t.Errorf("content type not preserved: %v (expected %v)", verified.Payload.ContentType, exampleContentType)
	}
	if verified.Payload.Version != exampleContentVersion {
		t.Errorf("content version not preserved: %v (expected %v)", verified.Payload.Version, exampleContentVersion)
	}
	if verified.Payload.LastModified != now.Truncate(time.Second) {
		t.Errorf("modification time not preserved: %v (expected %v)", verified.Payload.LastModified, now)
	}

	var verifiedPayload examplePayload
	rest, err := encodingASN1.Unmarshal(verified.Payload.Data.FullBytes, &verifiedPayload)
	if err != nil {
		t.Errorf("failed to unmarshal verfified payload: %v", err)
	}
	if len(rest) != 0 {
		t.Errorf("verfified payload contains %v extra bytes", len(rest))
	}

	if (verifiedPayload.Value1 != 0xADEAD) || (verifiedPayload.Value2 != 0xBEE) {
		t.Errorf("verfified payload data is not intact")
	}
}

func TestEmptySignature(t *testing.T) {
	s, err := NewNotary(new(testKeyedHmac))
	if err != nil {
		t.Fatalf("newNotary() failed: %v", err)
	}

	// Manually construct and serialize container without signatures in it
	container := asn1.SignedContainer{
		Payload: asn1.SignedPayload{
			Data: 42,
		},
		Signatures: make([]asn1.Signature, 0),
	}
	data, err := encodingASN1.Marshal(container)
	if err != nil {
		t.Fatalf("failed to marshal empty payload: %v", err)
	}

	verified, err := s.Verify(data, context)
	if err != ErrNoSignature {
		t.Errorf("unexpected verification error: %v", err)
	}
	if verified != nil {
		t.Errorf("verfied data without signatures")
	}
}

var honestOID = encodingASN1.ObjectIdentifier([]int{2, 7, 18, 28, 18, 28})

func TestUnknownSignature(t *testing.T) {
	s, err := NewNotary(new(testKeyedHmac))
	if err != nil {
		t.Fatalf("newNotary() failed: %v", err)
	}

	// Manually construct and serialize container with one unknown signature in it
	container := asn1.SignedContainer{
		Payload: asn1.SignedPayload{
			Data: 42,
		},
		Signatures: []asn1.Signature{asn1.Signature{
			Algorithm: honestOID,
			Signature: []byte("real thing, trust me"),
		}},
	}
	data, err := encodingASN1.Marshal(container)
	if err != nil {
		t.Fatalf("failed to marshal demo payload: %v", err)
	}

	verified, err := s.Verify(data, context)
	if err != ErrNoSignature {
		t.Errorf("unexpected verification error: %v", err)
	}
	if verified != nil {
		t.Errorf("verfied data with unknown signatures")
	}
}

func TestBrokenSignature(t *testing.T) {
	s, err := NewNotary(new(testKeyedHmac))
	if err != nil {
		t.Fatalf("newNotary() failed: %v", err)
	}

	container := asn1.SignedContainer{Payload: asn1.SignedPayload{
		Data: 42,
	}}
	data, err := s.Sign(&container, context)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	// It's unexpectedly hard to find a byte in DER data which you can flip
	// without breaking DER parsing itself, but we know that the signatures
	// are in the end so we can easily break them at least
	data[len(data)-1] = data[len(data)-1] ^ 0xFF

	verified, err := s.Verify(data, context)
	if err != ErrSignatureError {
		t.Errorf("unexpected verification error: %v", err)
	}
	if verified != nil {
		t.Errorf("verfied corrupted data")
	}
}
