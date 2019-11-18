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

package base

import (
	"context"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/sirupsen/logrus"
)

// DataProcessor for data from database with AcraStructs
type DataProcessor interface {
	Process(data []byte, context *DataProcessorContext) ([]byte, error)
}

// ProcessorFunc cast function to cast function as DataProcessor
type ProcessorFunc func([]byte, *DataProcessorContext) ([]byte, error)

// Process cast ProcessorFunc to DataProcessor interface
func (f ProcessorFunc) Process(data []byte, ctx *DataProcessorContext) ([]byte, error) {
	return f(data, ctx)
}

// ProcessorWrapper interface for wrappers of DataProcessor
type ProcessorWrapper interface {
	Wrap(DataProcessor) DataProcessor
}

// DecryptProcessor default implementation of DataProcessor with AcraStruct decryption
type DecryptProcessor struct{}

func NewDecryptProcessor(processor DataProcessor) DataProcessor {
	return ProcessorFunc(func(data []byte, context *DataProcessorContext) ([]byte, error) {
		data, err := processor.Process(data, context)
		if err != nil {
			return data, err
		}
		return DecryptProcessor{}.Process(data, context)
	})
}

// Process implement DataProcessor with AcraStruct decryption
func (DecryptProcessor) Process(data []byte, context *DataProcessorContext) ([]byte, error) {
	var privateKey *keys.PrivateKey
	var err error
	if context.WithZone {
		privateKey, err = context.Keystore.GetZonePrivateKey(context.ZoneID)
	} else {
		privateKey, err = context.Keystore.GetServerDecryptionPrivateKey(context.ClientID)
	}
	if err != nil {
		logging.GetLoggerFromContext(context.Context).WithError(err).WithFields(
			logrus.Fields{"client_id": string(context.ClientID), "zone_id": context.ZoneID}).Warningln("Can't read private key for matched client_id/zone_id")
		return []byte{}, err
	}
	return DecryptAcrastruct(data, privateKey, context.ZoneID)
}

// DataProcessorContext store data for DataProcessor
type DataProcessorContext struct {
	ClientID []byte
	ZoneID   []byte
	WithZone bool
	Keystore keystore.PrivateKeyStore
	Context  context.Context
}

// NewDataProcessorContext return context with initialized static data
func NewDataProcessorContext(clientID []byte, withZone bool, keystore keystore.PrivateKeyStore) *DataProcessorContext {
	return &DataProcessorContext{ClientID: clientID, WithZone: withZone, Keystore: keystore, Context: context.Background()}
}

// Reset ZoneID and context and return itself
func (ctx *DataProcessorContext) Reset() *DataProcessorContext {
	ctx.ZoneID = nil
	ctx.Context = context.Background()
	return ctx
}

// UseZoneID replace ZoneID and return itself
func (ctx *DataProcessorContext) UseZoneID(id []byte) *DataProcessorContext {
	ctx.ZoneID = id
	return ctx
}

// UseContext replace context and return itself
func (ctx *DataProcessorContext) UseContext(newContext context.Context) *DataProcessorContext {
	ctx.Context = newContext
	return ctx
}
