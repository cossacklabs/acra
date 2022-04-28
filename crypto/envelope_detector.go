package crypto

import (
	"bytes"
	"context"
	"errors"
	"github.com/cossacklabs/acra/acrablock"
	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
)

// EnvelopeCallbackHandler define callback method that called on each found serialized container
type EnvelopeCallbackHandler interface {
	OnCryptoEnvelope(ctx context.Context, container []byte) ([]byte, error)
	ID() string
}

// EnvelopeDetector try to find serialized container in data block and map it to its internal callbacks list
type EnvelopeDetector struct {
	callbacks []EnvelopeCallbackHandler
}

// NewEnvelopeDetector construct new EnvelopeDetector with list of callback
func NewEnvelopeDetector() *EnvelopeDetector {
	return &EnvelopeDetector{
		callbacks: make([]EnvelopeCallbackHandler, 0, 2),
	}
}

// AddCallback adds callback its list
func (recognizer *EnvelopeDetector) AddCallback(callback EnvelopeCallbackHandler) {
	recognizer.callbacks = append(recognizer.callbacks, callback)
}

// OnCryptoEnvelope try to match container for its underlying callbacks
func (recognizer *EnvelopeDetector) OnCryptoEnvelope(ctx context.Context, container []byte) ([]byte, error) {
	for _, handler := range recognizer.callbacks {
		processedData, err := handler.OnCryptoEnvelope(ctx, container)
		if err != nil {
			if errors.Is(err, ErrDecryptionError) {
				continue
			}
			logrus.WithError(err).WithField("callback", handler.ID()).Debugln("EnvelopeDetector.OnCryptoEnvelope failed to process container")
			return container, err
		}

		if !bytes.Equal(processedData, container) {
			return processedData, nil
		}
	}

	return container, nil
}

// OnColumn callback which find serializedContainer in inBuffer and try to process it with its callbacks
func (recognizer *EnvelopeDetector) OnColumn(ctx context.Context, inBuffer []byte) (context.Context, []byte, error) {
	logrus.Debugln("OnColumn: Try to decrypt SerializedContainer")
	if len(inBuffer) < SerializedContainerMinSize || len(recognizer.callbacks) == 0 {
		return ctx, inBuffer, nil
	}
	outBuffer := make([]byte, 0, len(inBuffer))
	changed := false
	// inline mode
	inIndex := 0
	for {
		beginTagIndex := bytes.Index(inBuffer[inIndex:], TagBegin)
		if beginTagIndex == utils.NotFound {
			break
		}
		beginTagIndex += inIndex
		outBuffer = append(outBuffer, inBuffer[inIndex:beginTagIndex]...)
		inIndex = beginTagIndex
		n, container, err := ExtractSerializedContainer(inBuffer[inIndex:])
		if err != nil {
			outBuffer = append(outBuffer, inBuffer[inIndex])
			inIndex++
			continue
		}

		var processedData []byte
		for index, handler := range recognizer.callbacks {
			processedData, err = handler.OnCryptoEnvelope(ctx, container)
			if err != nil {
				if errors.Is(err, ErrDecryptionError) {
					if index == len(recognizer.callbacks)-1 {
						outBuffer = append(outBuffer, inBuffer[inIndex])
						inIndex++
					}
					continue
				}
				logrus.WithError(err).WithField("callback", handler.ID()).Debugln("EnvelopeDetector.OnCryptoEnvelope failed to process container")
				return ctx, inBuffer, err
			}

			// callback managed to decrypt data, put it decrypted in the outBuffer and shift on the number of container length
			if !bytes.Equal(processedData, container) {
				outBuffer = append(outBuffer, processedData...)
				inIndex += n
				changed = true
				break
			}

			// means that all callbacks can't decrypt data, so we need just to shift on one byte and try to find new container
			if bytes.Equal(processedData, container) && index == len(recognizer.callbacks)-1 {
				outBuffer = append(outBuffer, inBuffer[inIndex])
				inIndex++
				break
			}
		}
	}
	// copy left bytes
	outBuffer = append(outBuffer, inBuffer[inIndex:]...)
	if changed {
		return base.MarkDecryptedContext(ctx), outBuffer, nil
	}
	return ctx, outBuffer, nil
}

// ID return identifier os this processor
func (*EnvelopeDetector) ID() string {
	return "EnvelopeDetector processor"
}

// OldContainerDetectorWrapper wraps EnvelopeDetector with additional functionality for tracking raw AcraStructs or AcraBlock for saving backward compatibility
type OldContainerDetectorWrapper struct {
	detector *EnvelopeDetector
	// flag used for notification of any found crypto envelope during OnColumn processing
	hasMatchedEnvelope bool
}

// ID return identifier of this processor
func (wrapper *OldContainerDetectorWrapper) ID() string {
	return "OldContainerDetectorWrapper"
}

// NewOldContainerDetectorWrapper construct new OldContainerDetectorWrapper with provided EnvelopeDetector
func NewOldContainerDetectorWrapper(detector *EnvelopeDetector) *OldContainerDetectorWrapper {
	wrapper := &OldContainerDetectorWrapper{
		detector: detector,
	}

	// we need to add wrapper to detector callback list to control the state of `hasMatchedEnvelope` variable
	// without it OldContainerDetectorWrapper will work in mode of detecting AcraStruct/AcraBlocks ONLY!
	detector.AddCallback(wrapper)
	return wrapper
}

// OnAcraStruct implementation of acrastruct.Processor
func (wrapper *OldContainerDetectorWrapper) OnAcraStruct(ctx context.Context, acraStruct []byte) ([]byte, error) {
	serialized, err := SerializeEncryptedData(acraStruct, AcraStructEnvelopeID)
	if err != nil {
		return nil, err
	}

	processedData, err := wrapper.detector.OnCryptoEnvelope(ctx, serialized)
	if err != nil {
		return nil, err
	}

	// return old container in case of unavailability to decrypt it
	if bytes.Equal(processedData, serialized) {
		return acraStruct, nil
	}

	return processedData, nil
}

// OnAcraBlock implementation of acrablock.Processor
func (wrapper *OldContainerDetectorWrapper) OnAcraBlock(ctx context.Context, acraBlock acrablock.AcraBlock) ([]byte, error) {
	serialized, err := SerializeEncryptedData(acraBlock, AcraBlockEnvelopeID)
	if err != nil {
		return nil, err
	}

	processedData, err := wrapper.detector.OnCryptoEnvelope(ctx, serialized)
	if err != nil {
		return nil, err
	}

	// return old container in case of unavailability to decrypt it
	if bytes.Equal(processedData, serialized) {
		return acraBlock, nil
	}

	return processedData, nil
}

// OnCryptoEnvelope used to pretend BackWrapper as callback for EnvelopeDetector
// and switches hasMatchedEnvelope flag to know that EnvelopeDetector matched new container during its OnColumn processing
func (wrapper *OldContainerDetectorWrapper) OnCryptoEnvelope(ctx context.Context, container []byte) ([]byte, error) {
	wrapper.hasMatchedEnvelope = true
	return container, nil
}

// OnColumn callback which finds serializedContainer or AcraStruct/AcraBlock for backward compatibility
func (wrapper *OldContainerDetectorWrapper) OnColumn(ctx context.Context, inBuffer []byte) (context.Context, []byte, error) {
	// we should track that if incoming data contains any signs of new container and if it is we return data as is
	// otherwise try to search for AcraBlock or AcraStruct to save backward compatibility
	// so before any OnColumn we should reset hasMatchedEnvelope flag to track if its changed during EnvelopeDetector OnColumn via BackWrapper.OnCryptoEnvelope callback
	wrapper.hasMatchedEnvelope = false

	ctx, newResult, err := wrapper.detector.OnColumn(ctx, inBuffer)
	if err != nil {
		return ctx, newResult, err
	}

	if wrapper.hasMatchedEnvelope || !bytes.Equal(newResult, inBuffer) {
		return ctx, newResult, nil
	}

	outBuffer := make([]byte, len(inBuffer))
	outBuffer, err = acrastruct.ProcessAcraStructs(ctx, inBuffer, outBuffer, wrapper)
	if err != nil {
		return ctx, inBuffer, err
	}

	outBuffer, err = acrablock.ProcessAcraBlocks(ctx, outBuffer, outBuffer, wrapper)
	if err != nil {
		return ctx, inBuffer, err
	}
	if !bytes.Equal(inBuffer, outBuffer) {
		return base.MarkDecryptedContext(ctx), outBuffer, nil
	}

	return ctx, outBuffer, nil
}
