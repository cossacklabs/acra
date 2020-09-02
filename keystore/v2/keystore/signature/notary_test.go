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
	"bytes"
	encodingASN1 "encoding/asn1"
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

type echoSignature struct{}

func (*echoSignature) AlgorithmOID() encodingASN1.ObjectIdentifier {
	return encodingASN1.ObjectIdentifier([]int{1, 1, 1, 1})
}

func (*echoSignature) Sign(data, context []byte) []byte {
	result := make([]byte, 0, len(data)+len(context))
	result = append(result, data...)
	result = append(result, context...)
	return result
}

func (*echoSignature) Verify(signature, data, context []byte) bool {
	expected := make([]byte, 0, len(data)+len(context))
	expected = append(expected, data...)
	expected = append(expected, context...)
	return bytes.Equal(expected, signature)
}

func testSignAlgorithms(t *testing.T) []Algorithm {
	return []Algorithm{&echoSignature{}}
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

	algorithms := testSignAlgorithms(t)
	s, err := NewNotary(algorithms)
	if err != nil {
		t.Fatalf("newNotary() failed: %v", err)
	}

	signed, err := s.Sign(&container, context)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	if len(container.Signatures) != len(algorithms) {
		t.Errorf("invalid signature count")
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
	// ASN.1 does not preserve subsecond precision
	nowSeconds := now.Truncate(time.Second)
	if !verified.Payload.LastModified.Equal(nowSeconds) {
		t.Errorf("modification time not preserved: %v (expected %v)", verified.Payload.LastModified, nowSeconds)
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
	s, err := NewNotary(testSignAlgorithms(t))
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
	s, err := NewNotary(testSignAlgorithms(t))
	if err != nil {
		t.Fatalf("newNotary() failed: %v", err)
	}

	// Manually construct and serialize container with one unknown signature in it
	container := asn1.SignedContainer{
		Payload: asn1.SignedPayload{
			Data: 42,
		},
		Signatures: []asn1.Signature{{
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
	s, err := NewNotary(testSignAlgorithms(t))
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

func TestMissingAlgorithms(t *testing.T) {
	_, err := NewNotary(nil)
	if err != ErrNoAlgorithms {
		t.Errorf("NewNotary() failed: %v", err)
	}
}
