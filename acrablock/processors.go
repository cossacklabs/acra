package acrablock

import (
	"bytes"
	"context"
	"errors"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
)

// DecryptProcessor default implementation of DataProcessor with AcraStruct decryption
type DecryptProcessor struct {
	keyStore keystore.SymmetricEncryptionKeyStore
}

// NewDecryptProcessor return initialized processor for AcraBlock decryption
func NewDecryptProcessor(keyStore keystore.SymmetricEncryptionKeyStore) (*DecryptProcessor, error) {
	return &DecryptProcessor{keyStore}, nil
}

var errDecryptionError = errors.New("decryption error")

// Process implement DataProcessor with AcraStruct decryption
func (processor *DecryptProcessor) Process(data []byte, context *base.DataProcessorContext) ([]byte, error) {
	logrus.Debugln("Process: Decrypt AcraBlock")
	acraBlock, err := NewAcraBlockFromData(data)
	if err != nil {
		return data, err
	}
	var privateKeys [][]byte
	accessContext := base.AccessContextFromContext(context.Context)
	var zoneID []byte
	if accessContext.IsWithZone() {
		// skip if not matched by previous processor
		if accessContext.GetZoneID() == nil {
			return data, nil
		}
		privateKeys, err = processor.keyStore.GetZoneIDSymmetricKeys(accessContext.GetZoneID())
		zoneID = accessContext.GetZoneID()
	} else {
		privateKeys, err = processor.keyStore.GetClientIDSymmetricKeys(accessContext.GetClientID())
		zoneID = nil
	}
	defer utils.ZeroizeSymmetricKeys(privateKeys)
	if err != nil {
		logging.GetLoggerFromContext(context.Context).WithError(err).WithFields(
			logrus.Fields{"client_id": string(accessContext.GetClientID()), "zone_id": string(accessContext.GetZoneID())}).Warningln("Can't read private key for matched client_id/zone_id")
		return []byte{}, err
	}
	decrypted, err := acraBlock.Decrypt(privateKeys, zoneID)
	if err != nil {
		logging.GetLoggerFromContext(context.Context).WithError(err).Errorln("Can't decrypt AcraBlock")
		return nil, errDecryptionError
	}
	logrus.WithField("context", string(zoneID)).Debugln("Decrypted Acrablock")
	return decrypted, nil
}

// MatchDataSignature return true if data has valid AcraBlock signature
func (*DecryptProcessor) MatchDataSignature(data []byte) bool {
	_, _, err := ExtractAcraBlockFromData(data)
	return err == nil
}

// OnColumnProcessor find AcraBlocks in data passed to OnColumn callback and pass them to processor
type OnColumnProcessor struct {
	processor base.DataProcessor
}

// NewOnColumnProcessor return new OnColumnProcessor initialized with processor
func NewOnColumnProcessor(processor base.DataProcessor) *OnColumnProcessor {
	return &OnColumnProcessor{processor}
}

// OnColumn callback which find AcraBlocks in inBuffer, decrypts and return new buffer
func (processor *OnColumnProcessor) OnColumn(ctx context.Context, inBuffer []byte) (context.Context, []byte, error) {
	logrus.Debugln("OnColumn: Try to decrypt AcraBlock")
	if len(inBuffer) < AcraBlockMinSize {
		return ctx, inBuffer, nil
	}
	outBuffer := make([]byte, 0, len(inBuffer))
	// inline mode
	inIndex := 0
	for {
		beginTagIndex := bytes.Index(inBuffer[inIndex:], tagBegin)
		if beginTagIndex == utils.NotFound {
			break
		}
		beginTagIndex += inIndex
		outBuffer = append(outBuffer, inBuffer[inIndex:beginTagIndex]...)
		inIndex = beginTagIndex
		n, acraBlock, err := ExtractAcraBlockFromData(inBuffer[inIndex:])
		if err != nil {
			outBuffer = append(outBuffer, inBuffer[inIndex])
			inIndex++
			continue
		}
		decrypted, err := processor.processor.Process(acraBlock, &base.DataProcessorContext{Context: ctx})
		if err != nil {
			if err == errDecryptionError {
				outBuffer = append(outBuffer, inBuffer[inIndex])
				inIndex++
				continue
			}
			return ctx, inBuffer, err
		}
		outBuffer = append(outBuffer, decrypted...)
		inIndex += n
	}
	// copy left bytes
	outBuffer = append(outBuffer, inBuffer[inIndex:]...)
	return ctx, outBuffer, nil
}

// ID return identifier os this processor
func (*OnColumnProcessor) ID() string {
	return "AcraBlock processor"
}
