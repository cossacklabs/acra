package crypto

import (
	"context"
	"github.com/cossacklabs/acra/decryptor/base"
)

// EnvelopeMatcher match CryptoEnvelope signatures in data blobs. It matches all registered CryptoEnvelopes
// and with base.OldContainerDetectionOn flag also matches pure AcraStruct/AcraBlocks
type EnvelopeMatcher struct {
	detector base.DecryptionSubscriber
	matched  bool
}

// NewEnvelopeMatcher return initialized EnvelopeMatcher
func NewEnvelopeMatcher() *EnvelopeMatcher {
	envelopeDetector := NewEnvelopeDetector()
	var detector base.DecryptionSubscriber = envelopeDetector
	if base.OldContainerDetectionOn {
		detector = NewOldContainerDetectorWrapper(envelopeDetector)
	}
	matcher := &EnvelopeMatcher{detector: detector}
	envelopeDetector.AddCallback(matcher)
	return matcher
}

// Match return true if data is any of known CryptoEnvelope
func (matcher *EnvelopeMatcher) Match(data []byte) bool {
	matcher.detector.OnColumn(context.TODO(), data)
	result := matcher.matched
	matcher.matched = false
	return result
}

// ID return identifier
func (matcher *EnvelopeMatcher) ID() string {
	return "EnvelopeMatcher"
}

// OnCryptoEnvelope callback for EnveloperDetector to up flag that matched CryptoEnvelope
func (matcher *EnvelopeMatcher) OnCryptoEnvelope(ctx context.Context, container []byte) ([]byte, error) {
	matcher.matched = true
	return container, nil
}
