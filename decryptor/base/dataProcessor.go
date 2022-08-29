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
	"fmt"
	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/sirupsen/logrus"
)

// OldContainerDetectionOn is a stub for CLI/buildFlags configuration for containers detection
const OldContainerDetectionOn = true

// DataProcessor for data from database with AcraStructs
type DataProcessor interface {
	Process(data []byte, context *DataProcessorContext) ([]byte, error)
}

// ExtendedDataProcessor extended with MatchDataSignature method to filter incoming data and skip extra processing
type ExtendedDataProcessor interface {
	DataProcessor
	MatchDataSignature([]byte) bool
}

// ProcessorFunc cast function to cast function as DataProcessor
type ProcessorFunc func([]byte, *DataProcessorContext) ([]byte, error)

// Process cast ProcessorFunc to DataProcessor interface
func (f ProcessorFunc) Process(data []byte, ctx *DataProcessorContext) ([]byte, error) {
	return f(data, ctx)
}

// ChainProcessorWrapper chain of processors which store all processors and call all of them until one return decrypted data
type ChainProcessorWrapper struct {
	processors []ExtendedDataProcessor
}

// NewChainProcessorWrapper return wrapped processor
func NewChainProcessorWrapper(processors ...ExtendedDataProcessor) *ChainProcessorWrapper {
	return &ChainProcessorWrapper{processors}
}

// Process cast ProcessorFunc to DataProcessor interface
func (d *ChainProcessorWrapper) Process(inData []byte, ctx *DataProcessorContext) (data []byte, err error) {
	for _, p := range d.processors {
		data, err = p.Process(inData, ctx)
		if err == nil {
			return data, nil
		}
	}
	return inData, err
}

// MatchDataSignature call MatchDataSignature for all wrapped processors and return true if any of them return true otherwise false
func (d *ChainProcessorWrapper) MatchDataSignature(data []byte) bool {
	for _, p := range d.processors {
		if p.MatchDataSignature(data) {
			return true
		}
	}
	return false
}

// ProcessorWrapper interface for wrappers of DataProcessor
type ProcessorWrapper interface {
	Wrap(DataProcessor) DataProcessor
}

// DecryptProcessor default implementation of DataProcessor with AcraStruct decryption
type DecryptProcessor struct{}

// Process implement DataProcessor with AcraStruct decryption
func (p DecryptProcessor) Process(data []byte, context *DataProcessorContext) ([]byte, error) {
	if err := acrastruct.ValidateAcraStructLength(data); err != nil {
		return data, err
	}
	var privateKeys []*keys.PrivateKey
	accessContext := AccessContextFromContext(context.Context)
	privateKeys, err := context.Keystore.GetServerDecryptionPrivateKeys(accessContext.GetClientID())
	defer utils.ZeroizePrivateKeys(privateKeys)
	if err != nil {
		logging.GetLoggerFromContext(context.Context).WithError(err).WithFields(
			logrus.Fields{"client_id": string(accessContext.GetClientID())}).Warningln("Can't read private key for matched client_id")
		return []byte{}, err
	}
	return acrastruct.DecryptRotatedAcrastruct(data, privateKeys, nil)
}

// MatchDataSignature return true if data has valid AcraStruct signature
func (DecryptProcessor) MatchDataSignature(data []byte) bool {
	return acrastruct.ValidateAcraStructLength(data) == nil
}

// DataProcessorContext store data for DataProcessor
type DataProcessorContext struct {
	Keystore keystore.DataEncryptorKeyStore
	Context  context.Context
}

// NewDataProcessorContext return context with initialized static data
func NewDataProcessorContext(keystore keystore.DataEncryptorKeyStore) *DataProcessorContext {
	return &DataProcessorContext{Keystore: keystore, Context: context.Background()}
}

// UseContext replace context and return itself
func (ctx *DataProcessorContext) UseContext(newContext context.Context) *DataProcessorContext {
	ctx.Context = newContext
	return ctx
}

// CheckReadWrite check that n == expectedN and err != nil
func CheckReadWrite(n, expectedN int, err error) error {
	if err != nil {
		return err
	}
	if n != expectedN {
		return fmt.Errorf("incorrect read/write count. %d != %d", n, expectedN)
	}
	return nil
}
