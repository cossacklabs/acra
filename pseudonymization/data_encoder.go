package pseudonymization

import (
	"context"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/pseudonymization/common"
)

// TokenProcessor implements processor which tokenize/detokenize data for acra-server used in decryptor module
type TokenProcessor struct {
	tokenizer *DataTokenizer
}

// NewTokenProcessor return new processor
func NewTokenProcessor(tokenizer *DataTokenizer) (*TokenProcessor, error) {
	return &TokenProcessor{tokenizer}, nil
}

// ID return name of processor
func (p *TokenProcessor) ID() string {
	return "TokenProcessor"
}

// OnColumn tokenize data if configured by encryptor config
func (p *TokenProcessor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	accessContext := base.AccessContextFromContext(ctx)
	columnSetting, ok := encryptor.EncryptionSettingFromContext(ctx)
	if ok && columnSetting.IsTokenized() {
		tokenContext := common.TokenContext{ClientID: accessContext.GetClientID(), AdditionalContext: accessContext.GetAdditionalContext()}
		data, err := p.tokenizer.Detokenize(data, tokenContext, columnSetting)
		if err != nil {
			if err != ErrDataTypeMismatch {
				base.AcraDetokenizationCounter.WithLabelValues(base.LabelStatusFail, columnSetting.GetTokenType().String()).Inc()
			}
			return ctx, data, err
		}

		base.AcraDetokenizationCounter.WithLabelValues(base.LabelStatusSuccess, columnSetting.GetTokenType().String()).Inc()
		return ctx, data, nil
	}
	return ctx, data, nil
}
