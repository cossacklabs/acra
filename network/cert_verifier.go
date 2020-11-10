package network

import (
	"crypto/x509"
	log "github.com/sirupsen/logrus"
)

// CertVerifier is a generic certificate verifier
type CertVerifier interface {
	// Verify returns number of confirmations or error.
	// The error is returned only if it is critical, for example:
	// - the certificate was revoked
	// - (for OCSP) the certificate is not known by OCSP server and we requested tls_ocsp_required == "yes" or "all"
	// - (for OCSP) if we were unable to contact OCSP server(s) but we really need the response, tls_ocsp_required == "all"
	Verify(chain []*x509.Certificate) (int, error)
}

// NewCertVerifierFromConfigs creates a CertVerifier based on passed OCSP and CRL configs
func NewCertVerifierFromConfigs(ocspConfig *OCSPConfig, crlConfig *CRLConfig) (CertVerifier, error) {
	certVerifier := NewCertVerifierAll()

	if ocspConfig != nil {
		if ocspConfig.url != "" || ocspConfig.fromCert != ocspFromCertIgnore {
			log.Debugln("NewCertVerifierFromConfigs(): adding OCSP verifier")
			ocspVerifier := DefaultOCSPVerifier{Config: *ocspConfig, Client: &DefaultOCSPClient{}}
			certVerifier.Push(ocspVerifier)
		}
	}

	if crlConfig != nil {
		if crlConfig.uri != "" || crlConfig.fromCert != crlFromCertIgnore {
			log.Debugln("NewCertVerifierFromConfigs(): adding CRL verifier")
			crlVerifier := DefaultCRLVerifier{Config: *crlConfig, Client: DefaultCRLClient{}, Cache: &DefaultCRLCache{}}
			certVerifier.Push(crlVerifier)
		}
	}

	return certVerifier, nil
}

// CertVerifierAll is an implementation of CertVerifier that requires all verifiers to return success
type CertVerifierAll struct {
	verifiers []CertVerifier
}

// NewCertVerifierAll creates new CertVerifierAll, verifier that tries all internally contained verifiers
func NewCertVerifierAll(verifiers ...CertVerifier) CertVerifierAll {
	return CertVerifierAll{verifiers: verifiers}
}

// Push append one more verifier to internal list
func (v *CertVerifierAll) Push(verifier CertVerifier) {
	v.verifiers = append(v.verifiers, verifier)
}

// Verify returns number of confirmations or error
func (v CertVerifierAll) Verify(chain []*x509.Certificate) (int, error) {
	confirmsTotal := 0

	for _, verifier := range v.verifiers {
		confirms, err := verifier.Verify(chain)
		if err != nil {
			return confirmsTotal, err
		}
		confirmsTotal += confirms
	}

	return confirmsTotal, nil
}
