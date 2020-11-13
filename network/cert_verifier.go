/*
Copyright 2020, Cossack Labs Limited

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

package network

import (
	"crypto/x509"
	log "github.com/sirupsen/logrus"
)

// CertVerifier is a generic certificate verifier
type CertVerifier interface {
	// Verify checks whether the certificate is revoked.
	// The error is returned if:
	// - the certificate was revoked
	// - (for OCSP) the certificate is not known by OCSP server and we requested tls_ocsp_required == "yes" or "all"
	// - (for OCSP) if we were unable to contact OCSP server(s) but we really need the response, tls_ocsp_required == "all"
	Verify(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
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
			crlVerifier := DefaultCRLVerifier{Config: *crlConfig, Client: NewDefaultCRLClient(), Cache: &DefaultCRLCache{}, ParsedCache: NewLRUParsedCRLCache(16)}
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
func (v CertVerifierAll) Verify(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	for _, verifier := range v.verifiers {
		err := verifier.Verify(rawCerts, verifiedChains)
		if err != nil {
			log.WithError(err).Debugln("Certificate verification failed")
			return err
		}
	}

	return nil
}
