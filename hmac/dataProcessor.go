/*
Copyright 2018, Cossack Labs Limited

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

package hmac

import (
	"context"
	"errors"
	"github.com/cossacklabs/acra/acrablock"
	acrastruct2 "github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/themis/gothemis/keys"
)

// ErrHMACNotMatch hmac not equal to data in AcraStruct
var ErrHMACNotMatch = errors.New("HMAC not match to data in AcraStruct")

//Processor HMAC DataProcessor implementation
type Processor struct {
	hashData        []byte
	matchedHash     Hash
	rawData         []byte
	hmacStore       keystore.HmacKeyStore
	envelopeMatcher *crypto.CryptoEnvelopeMatcher
}

// NewHMACProcessor return initialized HMACProcessor by provided keystore.HmacKeyStore)
func NewHMACProcessor(store keystore.HmacKeyStore) *Processor {
	matcher := crypto.NewCryptoEnvelopeMatcher()
	return &Processor{hmacStore: store, envelopeMatcher: matcher}
}

// ID return hardcoded HMAC ID
func (p *Processor) ID() string {
	return "HMAC processor"
}

// OnColumn return data itself if hash matched, otherwise column data hash will be returned
func (p *Processor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	_, err := p.Process(data, &base.DataProcessorContext{Context: ctx})
	if err != nil {
		logger := logging.GetLoggerFromContext(ctx)
		logger.WithError(err).Warning("Failed on HMAC processing")
		p.hashData = nil
		return ctx, p.rawData, nil
	}

	p.matchedHash = ExtractHash(data)
	if p.matchedHash == nil {
		p.hashData = nil
		return ctx, data, nil
	}
	if !p.envelopeMatcher.Match(data[p.matchedHash.Length():]) {
		p.matchedHash = nil
		return ctx, data, nil
	}
	p.rawData = make([]byte, len(data))
	// save initial data
	copy(p.rawData, data)

	p.hashData = p.rawData[:p.matchedHash.Length()]
	return ctx, data[p.matchedHash.Length():], nil
}

//Process HMAC DataProcessor implementation
func (p *Processor) Process(data []byte, ctx *base.DataProcessorContext) ([]byte, error) {
	accessContext := base.AccessContextFromContext(ctx.Context)
	if p.hashData != nil && !p.matchedHash.IsEqual(data, accessContext.GetClientID(), p.hmacStore) {
		return data, ErrHMACNotMatch
	}
	return data, nil
}

// WrapProcessor wrap HMACProcessor with provided DataProcessor
func (p *Processor) WrapProcessor(processor base.DataProcessor) base.DataProcessor {
	return base.ProcessorFunc(func(data []byte, ctx *base.DataProcessorContext) ([]byte, error) {
		data, err := processor.Process(data, ctx)
		if err != nil {
			return data, err
		}
		return p.Process(data, ctx)
	})
}

// NewHashProcessor extract hmac value data passed to DataProcessor.Process func and check hmac of data returned from processor
// by comparing with extracted hmac
func NewHashProcessor(processor base.DataProcessor, hmacStore keystore.HmacKeyStore) base.DataProcessor {
	return base.ProcessorFunc(func(data []byte, ctx *base.DataProcessorContext) ([]byte, error) {
		accessContext := base.AccessContextFromContext(ctx.Context)
		hash := ExtractHash(data)
		if hash == nil {
			return processor.Process(data, ctx)
		}
		data, err := processor.Process(data[hash.Length():], ctx)
		if err != nil {
			return data, err
		}
		if hash != nil && !hash.IsEqual(data, accessContext.GetClientID(), hmacStore) {
			return data, ErrHMACNotMatch
		}
		return data, nil
	})
}

// SimpleHmacKeyStore wrap byte slice and implement HmacKeyStore interface
type SimpleHmacKeyStore []byte

// GetHMACSecretKey return itself as key on any passed id
func (key SimpleHmacKeyStore) GetHMACSecretKey(id []byte) ([]byte, error) {
	return key, nil
}

// DecryptRotatedSearchableAcraStruct decrypt acrastruct with hash and verify that hash correct
// Note: function expects that AcraStruct was encrypted with key related to this context and hmacKey passed according to this context
// context should be ClientID or ZoneID
func DecryptRotatedSearchableAcraStruct(acrastruct []byte, hmacKey []byte, privateKeys []*keys.PrivateKey, context []byte) ([]byte, error) {
	hash := ExtractHash(acrastruct)
	if hash == nil {
		return acrastruct2.DecryptRotatedAcrastruct(acrastruct, privateKeys, context)
	}
	data, err := acrastruct2.DecryptRotatedAcrastruct(acrastruct[hash.Length():], privateKeys, context)
	if err != nil {
		return data, err
	}
	if !hash.IsEqual(data, context, SimpleHmacKeyStore(hmacKey)) {
		return data, ErrHMACNotMatch
	}
	return data, nil
}

// DecryptRotatedSearchableAcraBlock decrypt AcraBlock with hash and verify that hash correct
// Note: function expects that AcraBlock was encrypted with key related to this context and hmacKey passed according to this context
// context should be ClientID or ZoneID
func DecryptRotatedSearchableAcraBlock(acraBlock []byte, hmacKey []byte, symKeys [][]byte, context []byte) ([]byte, error) {
	hash := ExtractHash(acraBlock)
	if hash == nil {
		block, err := acrablock.NewAcraBlockFromData(acraBlock)
		if err != nil {
			return nil, err
		}
		return block.Decrypt(symKeys, context)
	}
	block, err := acrablock.NewAcraBlockFromData(acraBlock[hash.Length():])
	if err != nil {
		return block, err
	}
	data, err := block.Decrypt(symKeys, context)
	if err != nil {
		return nil, err
	}
	if !hash.IsEqual(data, context, SimpleHmacKeyStore(hmacKey)) {
		return data, ErrHMACNotMatch
	}
	return data, nil
}
