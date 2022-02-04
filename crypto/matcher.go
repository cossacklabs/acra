package crypto

import (
	"context"
	"github.com/cossacklabs/acra/decryptor/base"
)

type CryptoEnvelopeMatcher struct {
	detector base.DecryptionSubscriber
	matched  bool
}

func NewCryptoEnvelopeMatcher() *CryptoEnvelopeMatcher {
	envelopeDetector := NewEnvelopeDetector()
	var detector base.DecryptionSubscriber = envelopeDetector
	if base.OldContainerDetectionOn {
		detector = NewOldContainerDetectorWrapper(envelopeDetector)
	}
	matcher := &CryptoEnvelopeMatcher{detector: detector}
	envelopeDetector.AddCallback(matcher)
	return matcher
}

func (matcher *CryptoEnvelopeMatcher) Match(data []byte) bool {
	matcher.detector.OnColumn(context.TODO(), data)
	result := matcher.matched
	matcher.matched = false
	return result
}

func (matcher *CryptoEnvelopeMatcher) ID() string {
	return "CryptoEnvelopeMatcher"
}

func (matcher *CryptoEnvelopeMatcher) OnCryptoEnvelope(ctx context.Context, container []byte) ([]byte, error) {
	matcher.matched = true
	return container, nil
}
