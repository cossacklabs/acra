/*
Copyright 2020, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package common

import (
	"crypto/sha256"
	"errors"
	"time"
)

// TokenSetting describes how a column should be tokenized.
type TokenSetting interface {
	IsTokenized() bool
	IsConsistentTokenization() bool
	GetTokenType() TokenType
}

// ErrTokenNotFound error used when token wasn't found in storage
var ErrTokenNotFound = errors.New("token not found in storage")

// ErrTokenExists is returned by TokenStorage.Save when a token with given ID and context already exists in the storage
var ErrTokenExists = errors.New("token already exists")

// ErrTokenDisabled is returned when a token was found, but is explicitly disabled
var ErrTokenDisabled = errors.New("disabled token accessed")

// Encryptor interface used as abstraction for token encryption
type Encryptor interface {
	Encrypt(data, context TokenContext) ([]byte, error)
	Decrypt(data, context TokenContext) ([]byte, error)
}

// Email type used to separate string type from Email for tokens
type Email string

// TokenStorage interface abstracts storage implementation
type TokenStorage interface {
	Save(id []byte, context TokenContext, data []byte) error
	Get(id []byte, context TokenContext) ([]byte, error)
	Stat(id []byte, context TokenContext) (TokenMetadata, error)

	// Iterate over token metadata in the storage.
	// In addition to metadata, length of data for an entry is provided for reference. (Can't access data without context information).
	// The iteration order is unspecified. If the storage in concurrently modified during iteration,
	// modifications may or may not be visible during the iteration, and entries may be visited multiple times.
	// Return the desired action to do with the token, usually TokenContinue to simply continue iteration.
	// Return a non-nil error to stop iteration and return this error.
	VisitMetadata(cb func(dataLength int, metadata TokenMetadata) (TokenAction, error)) error

	SetAccessTimeGranularity(granularity time.Duration) error
}

// DefaultAccessTimeGranularity is the default difference in time required for the access time to be updated.
const DefaultAccessTimeGranularity = 24 * time.Hour

// TokenAction is an action to perform during VisitMetadata.
type TokenAction int

// Available TokenAction values.
const (
	TokenContinue TokenAction = iota
	TokenEnable
	TokenDisable
	TokenRemove
)

// Anonymizer interface provide all supported methods to anonymize data
type Anonymizer interface {
	// generic
	Anonymize(data interface{}, context TokenContext, dataType TokenType) (interface{}, error)

	// type specific
	AnonymizeInt32(value int32, context TokenContext) (int32, error)
	AnonymizeInt64(value int64, context TokenContext) (int64, error)
	AnonymizeBytes(value []byte, context TokenContext) ([]byte, error)
	AnonymizeStr(value string, context TokenContext) (string, error)
	AnonymizeEmail(email Email, context TokenContext) (Email, error)
}

// Pseudoanonymizer extends Anonymizer interface with methods to anonymize consistently and deanonymize value
type Pseudoanonymizer interface {
	Anonymizer
	AnonymizeConsistently(data interface{}, context TokenContext, dataType TokenType) (interface{}, error)
	Deanonymize(data interface{}, context TokenContext, dataType TokenType) (interface{}, error)
}

// TokenContext used as metadata for each token
type TokenContext struct {
	ClientID          []byte
	AdditionalContext []byte
}

// AggregateTokenContextToBytes used as function to return one byte array as value which is digest for context
func AggregateTokenContextToBytes(context TokenContext) []byte {
	h := sha256.New()
	if len(context.AdditionalContext) != 0 {
		// leave for backward compatibility when used zones
		h.Write([]byte(`zone`))
		h.Write(context.AdditionalContext)
	} else {
		h.Write([]byte(`client`))
		h.Write(context.ClientID)
	}
	return h.Sum(nil)
}
