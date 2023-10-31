package masking

import (
	"bytes"

	"github.com/cossacklabs/acra/decryptor/base"
	encryptor "github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/logging"
)

// Processor implements DataProcessor interface and unmask matched data
type Processor struct{ decryptor base.ExtendedDataProcessor }

// NewProcessor return new Processor for decryption masked data
func NewProcessor(decryptor base.ExtendedDataProcessor) (*Processor, error) {
	return &Processor{decryptor: decryptor}, nil
}

// Process implement DataProcessor with AcraStruct decryption
func (processor *Processor) Process(data []byte, context *base.DataProcessorContext) ([]byte, error) {
	logger := logging.GetLoggerFromContext(context.Context).WithField("processor", "masking")
	logger.Debugln("Processing masking")
	setting, ok := encryptor.EncryptionSettingFromContext(context.Context)
	if ok && setting.GetMaskingPattern() != "" {
		logger.Debugln("Has pattern")
		newData, err := processor.decryptor.Process(data, context)
		if err != nil || bytes.Equal(newData, data) {
			logger.Debugln("Mask data")
			return []byte(setting.GetMaskingPattern()), nil
		}
		logger.Debugln("Return decrypted")
		return newData, nil
	}
	return processor.decryptor.Process(data, context)
}
