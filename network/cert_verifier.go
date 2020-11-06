package network

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// CertVerifier is a generic certificate verifier
type CertVerifier interface {
	Verify(chain []*x509.Certificate) (int, error)
}

// CertVerifierAll is an implementation of CertVerifier that requires all verifiers to return success
type CertVerifierAll struct {
	verifiers []CertVerifier
}

// NewCertVerifierAll creates new CertVerifierAll, requires at least one verifier
func NewCertVerifierAll(verifiers ...CertVerifier) (*CertVerifierAll, error) {
	if len(verifiers) == 0 {
		return nil, errors.New("At least one verifier is expected in NewCertVerifierAll()")
	}

	return &CertVerifierAll{verifiers: verifiers}, nil
}

// Verify returns number of confirmations or error
func (v CertVerifierAll) Verify(chain []*x509.Certificate) (int, error) {
	confirmsTotal := 0

	for i := range v.verifiers {
		confirms, err := v.verifiers[i].Verify(chain)
		if err != nil {
			return confirmsTotal, err
		}
		// CertVerifierAll requires every verifier to give at least one confirmation
		if confirms == 0 {
			return confirmsTotal, errors.New("At least one confirmation required, but the verifier returned zero")
		}
		confirmsTotal += confirms
	}

	return confirmsTotal, nil
}

// CertVerifierAtLeast is an implementation of CertVerifier that requires at least one verifier to return success
type CertVerifierAtLeast struct {
	verifiers           []CertVerifier
	minConfirmsRequired int
}

// NewCertVerifierAtLeast creates new CertVerifierAtLeast
func NewCertVerifierAtLeast(confirms int, verifiers ...CertVerifier) (*CertVerifierAtLeast, error) {
	if len(verifiers) < confirms {
		return nil, fmt.Errorf("At least %d verifier(s) is expected in NewCertVerifierAtLeast()", confirms)
	}

	return &CertVerifierAtLeast{verifiers: verifiers, minConfirmsRequired: confirms}, nil
}

// Verify returns number of confirmations or error
func (v CertVerifierAtLeast) Verify(chain []*x509.Certificate) (int, error) {
	confirmsTotal := 0
	// how many verifiers from v.verifiers gave >0 confirms
	confirmsByVerifiers := 0

	for i := range v.verifiers {
		confirms, err := v.verifiers[i].Verify(chain)
		if err != nil {
			return confirmsTotal, err
		}
		confirmsTotal += confirms
		if confirms > 0 {
			confirmsByVerifiers++
		}
		// CertVerifierAtLeast will stop checking once we got >0 confirms from
		// at least v.minConfirmsRequired verifiers in v.verifiers
		if confirmsByVerifiers >= v.minConfirmsRequired {
			// Exception: if v.minConfirmsRequired == 0 and verifier returned
			// zero confirms, then try next verifiers
			if confirmsByVerifiers == 0 && confirms == 0 {
				continue
			}

			break
		}
	}

	if confirmsByVerifiers < v.minConfirmsRequired {
		return confirmsTotal, fmt.Errorf("Expected more-than-zero confirmations from %d verifiers, got %d", v.minConfirmsRequired, confirmsByVerifiers)
	}

	return confirmsTotal, nil
}
