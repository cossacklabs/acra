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

// Package asn1 contains descriptions of ASN.1 data structures used by Key Store.
package asn1

import (
	"encoding/asn1"
	"fmt"
	"time"
)

// Errors returned by ASN.1 processing:
var (
	ErrExtraData = fmt.Errorf("unexpected extra ASN.1 data")
)

// Miscellaneous ASN.1 constants:
var (
	// http://oid-info.com/get/2.16.840.1.101.3.4.2.1
	Sha256OID = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1})
)

// SignedContainer for a signed object. Every exported object of the key store
// is packed into a SignedContainer for storage. For example, file-based key
// store keeps a file for each key directory. Every file contains a SignedContainer
// with "ContentType" equal to 'TypeKeyDirectory' and a KeyDirectory stored
// in its "Data" field.
type SignedContainer struct {
	Payload    SignedPayload
	Signatures []Signature `asn1:"set"`
}

// Marshal into bytes.
func (container *SignedContainer) Marshal() ([]byte, error) {
	return asn1.Marshal(*container)
}

// VerifiedContainer is an unmarshaled form of SignedContainer.
type VerifiedContainer struct {
	Payload    VerifiedPayload
	Signatures []Signature `asn1:"set"`
}

// UnmarshalVerifiedContainer constructs a VerifiedContainer from serialized representation.
func UnmarshalVerifiedContainer(data []byte) (*VerifiedContainer, error) {
	container := new(VerifiedContainer)
	rest, err := asn1.Unmarshal(data, container)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, ErrExtraData
	}
	return container, nil
}

// We have to duplicate data definitions for containers because ASN.1's ANY type
// is represented by interface{} on input and asn1.RawValue on output.
// We cannot join them in a single structure to avoid duplication, unfortunately.

// SignedPayload contains payload for SignedContainer before marshaling.
type SignedPayload struct {
	ContentType  ContentType
	Version      int
	LastModified time.Time `asn1:"utc"`
	Data         interface{}
}

// Marshal into bytes.
func (payload *SignedPayload) Marshal() ([]byte, error) {
	return asn1.Marshal(*payload)
}

// VerifiedPayload contains payload of VerifiedContainer after unmarshaling.
type VerifiedPayload struct {
	RawContent   asn1.RawContent
	ContentType  ContentType
	Version      int
	LastModified time.Time `asn1:"utc"`
	Data         asn1.RawValue
}

// ContentType identifies "Data" field of SignedContainer objects.
type ContentType asn1.Enumerated

// Common ContentType constants:
const (
	TypeKeyRing ContentType = iota + 1
	TypeKeyDirectory
	TypeDirectKeyDirectory
	TypeEncryptedKeys
)

// Common Version constants:
const (
	KeyRingVersion2 = 2
)

// Signature for SignedContainer. A container can have multiple signatures
// made with different algorithms, enabling future-proofing, extensibility,
// and collision resistance. Signatures are computed for the "Payload" of
// SignedContainer, usually with HMAC keyed by the key store master key.
// The signing algorithm is indicated by the "Algorithm" field.
type Signature struct {
	Algorithm asn1.ObjectIdentifier
	Signature []byte
}

// DirectKeyDirectory contains key rings or other key directories.
// It has a name by which it can be referred to.
// Child key rings and directories are contained as immediate objects.
type DirectKeyDirectory struct {
	Name     LikelyUTF8String
	KeyRings []KeyRing            `asn1:"set,optional,tag:1"`
	Children []DirectKeyDirectory `asn1:"set,optional,tag:2"`
}

// KeyDirectory contains key rings or other key directories.
// It has a name by which it can be referred to.
type KeyDirectory struct {
	Name     LikelyUTF8String
	KeyRings []KeyRingReference      `asn1:"set,optional,tag:1"`
	Children []KeyDirectoryReference `asn1:"set,optional,tag:2"`
}

// UnmarshalKeyDirectory constructs a KeyDirectory from serialized representation.
func UnmarshalKeyDirectory(data []byte) (*KeyDirectory, error) {
	container := new(KeyDirectory)
	rest, err := asn1.Unmarshal(data, container)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, ErrExtraData
	}
	return container, nil
}

// EncryptedKeys is a set of key rings.
// It is typically used for backup purposes or to transfer keys between machines.
// SignedContainer actually contains an OCTET STRING with DER serialization of this object
// encrypted with Themis Secure Cell.
type EncryptedKeys struct {
	KeyRings []KeyRing `asn1:"set"`
}

// Marshal into bytes.
func (keys *EncryptedKeys) Marshal() ([]byte, error) {
	return asn1.Marshal(*keys)
}

// UnmarshalEncryptedKeys constructs EncryptedKeys from serialized representation.
func UnmarshalEncryptedKeys(data []byte) (*EncryptedKeys, error) {
	keys := new(EncryptedKeys)
	rest, err := asn1.Unmarshal(data, keys)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, ErrExtraData
	}
	return keys, nil
}

// KeyRingReference to a child key ring, not included into KeyDirectory object directly.
// However it can be located in some external memory using its name and the current
// directory path. Signatures are also provided for integrity validation.
// The key ring should be packed in SignedContainer.
type KeyRingReference struct {
	Name       LikelyUTF8String
	Signatures []Signature `asn1:"set"`
}

// KeyDirectoryReference to a child subdirectory, not included into KeyDirectory
// object directly. However it can be located in some external memory using its
// name and the current directory path. Signature are also provided for
// integrity validation. The directory should be packed in SignedContainer.
type KeyDirectoryReference struct {
	Name       LikelyUTF8String
	Signatures []Signature `asn1:"set"`
}

// KeyRing holds multiple versions of a key used for the same purpose. Keys
// are usually ordered from oldest to newest, with new keys added to the back
// of the sequence. One key in a key ring may be designated as 'current'.
type KeyRing struct {
	Purpose LikelyUTF8String
	Keys    []Key
	Current int
}

// NoKey indicates absence of key, such as for current key indication.
const NoKey = -1

// UnmarshalKeyRing constructs a KeyRing from serialized representation.
func UnmarshalKeyRing(data []byte) (*KeyRing, error) {
	r := new(KeyRing)
	rest, err := asn1.Unmarshal(data, r)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, ErrExtraData
	}
	return r, nil
}

// KeyWithSeqnum returns a reference to and index of the key with given seqnum.
// Returns nil and asn1.NoKey if the key ring contains no such key.
func (r *KeyRing) KeyWithSeqnum(seqnum int) (*Key, int) {
	// Iterate in reverse order since we're more likely to query recent keys.
	for i := len(r.Keys) - 1; i >= 0; i-- {
		if r.Keys[i].Seqnum == seqnum {
			return &r.Keys[i], i
		}
	}
	return nil, NoKey
}

// Key stored in the key store. The key is identified by its content and can have
// multiple representations. It also has some metadata pertaining to its usage
// restrictions.
type Key struct {
	Seqnum     int
	State      KeyState
	ValidSince time.Time `asn1:"utc"`
	ValidUntil time.Time `asn1:"utc"`
	Data       []KeyData `asn1:"set"`
}

// KeyState describes current state of the key.
type KeyState asn1.Enumerated

// Possible KeyState values:
const (
	KeyPreActive KeyState = iota + 1
	KeyActive
	KeySuspended
	KeyDeactivated
	KeyCompromised
	KeyDestroyed
)

// KeyData in a particular format.
type KeyData struct {
	Format       KeyFormat
	PublicKey    PublicKey    `asn1:"optional,tag:1"`
	PrivateKey   PrivateKey   `asn1:"optional,tag:2"`
	SymmetricKey SymmetricKey `asn1:"optional,tag:3"`
}

// KeyFormat describes format of KeyData.
type KeyFormat asn1.Enumerated

// Supported key formats:
const (
	ThemisKeyPairFormat KeyFormat = iota + 1
	_                             // reserved
	ThemisSymmetricKeyFormat
)

// PublicKey whish is stored in plaintext.
type PublicKey []byte

// PrivateKey which is stored encrypted.
type PrivateKey []byte

// SymmetricKey which is stored encrypted.
type SymmetricKey []byte

// LikelyUTF8String is used where human-readable UTF-8 is expected,
// but arbitrary bytes have to be actually allowed.
type LikelyUTF8String []byte
