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
	"errors"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"strings"
)

// Errors common for OCSP and CRL verifiers
var (
	ErrCertWasRevoked = errors.New("certificate was revoked")
	ErrEmptyCertChain = errors.New("empty verified certificates chain")
)

var (
	tlsOcspURL                      string
	tlsOcspClientURL                string
	tlsOcspDbURL                    string
	tlsOcspRequired                 string
	tlsOcspFromCert                 string
	tlsOcspCheckOnlyLeafCertificate bool
	tlsCrlURL                       string
	tlsCrlClientURL                 string
	tlsCrlDbURL                     string
	tlsCrlFromCert                  string
	tlsCrlCheckOnlyLeafCertificate  bool
	tlsCrlCacheSize                 uint
	tlsCrlCacheTime                 uint
)

// RegisterCertVerifierArgsForService register CLI args which allow to get CertVerifier by NewCertVerifier() for
// specified service
func RegisterCertVerifierArgsForService(flags *flag.FlagSet, serviceName string, namerFunc CLIParamNameConstructorFunc) {
	flags.String(namerFunc(serviceName, "url", "ocsp"), "", "OCSP service URL")
	flags.String(namerFunc(serviceName, "required", "ocsp"), OcspRequiredDenyUnknownStr,
		fmt.Sprintf("How to treat certificates unknown to OCSP: <%s>", strings.Join(OcspRequiredValuesList, "|")))
	flags.String(namerFunc(serviceName, "from_cert", "ocsp"), OcspFromCertPreferStr,
		fmt.Sprintf("How to treat OCSP server described in certificate itself: <%s>", strings.Join(OcspFromCertValuesList, "|")))
	flags.Bool(namerFunc(serviceName, "check_only_leaf_certificate", "ocsp"), false,
		"Put 'true' to check only final/last certificate, or 'false' to check the whole certificate chain using OCSP")
	flags.String(namerFunc(serviceName, "url", "crl"), "", "URL of the Certificate Revocation List (CRL) to use")
	flags.String(namerFunc(serviceName, "from_cert", "crl"), CrlFromCertPreferStr,
		fmt.Sprintf("How to treat CRL URL described in certificate itself: <%s>", strings.Join(CrlFromCertValuesList, "|")))
	flags.Bool(namerFunc(serviceName, "check_only_leaf_certificate", "crl"), false,
		"Put 'true' to check only final/last certificate, or 'false' to check the whole certificate chain using CRL")
	flags.Uint(namerFunc(serviceName, "cache_size", "crl"), CrlDefaultCacheSize, "How many CRLs to cache in memory (use 0 to disable caching)")
	flags.Uint(namerFunc(serviceName, "cache_time", "crl"), CrlDisableCacheTime,
		fmt.Sprintf("How long to keep CRLs cached, in seconds (use 0 to disable caching, maximum: %d s)", CrlCacheTimeMax))
}

// RegisterCertVerifierArgs register CLI args which allow to get CertVerifier by NewCertVerifier()
func RegisterCertVerifierArgs(flags *flag.FlagSet) {
	flags.StringVar(&tlsOcspURL, "tls_ocsp_url", "", "OCSP service URL")
	flags.StringVar(&tlsOcspRequired, "tls_ocsp_required", OcspRequiredDenyUnknownStr,
		fmt.Sprintf("How to treat certificates unknown to OCSP: <%s>", strings.Join(OcspRequiredValuesList, "|")))
	flags.StringVar(&tlsOcspFromCert, "tls_ocsp_from_cert", OcspFromCertPreferStr,
		fmt.Sprintf("How to treat OCSP server described in certificate itself: <%s>", strings.Join(OcspFromCertValuesList, "|")))
	flags.BoolVar(&tlsOcspCheckOnlyLeafCertificate, "tls_ocsp_check_only_leaf_certificate", false,
		"Put 'true' to check only final/last certificate, or 'false' to check the whole certificate chain using OCSP")
	flags.StringVar(&tlsCrlURL, "tls_crl_url", "", "URL of the Certificate Revocation List (CRL) to use")
	flags.StringVar(&tlsCrlFromCert, "tls_crl_from_cert", CrlFromCertPreferStr,
		fmt.Sprintf("How to treat CRL URL described in certificate itself: <%s>", strings.Join(CrlFromCertValuesList, "|")))
	flags.BoolVar(&tlsCrlCheckOnlyLeafCertificate, "tls_crl_check_only_leaf_certificate", false,
		"Put 'true' to check only final/last certificate, or 'false' to check the whole certificate chain using CRL")
	flags.UintVar(&tlsCrlCacheSize, "tls_crl_cache_size", CrlDefaultCacheSize, "How many CRLs to cache in memory (use 0 to disable caching)")
	flags.UintVar(&tlsCrlCacheTime, "tls_crl_cache_time", CrlDisableCacheTime,
		fmt.Sprintf("How long to keep CRLs cached, in seconds (use 0 to disable caching, maximum: %d s)", CrlCacheTimeMax))
}

// CertVerifier is a generic certificate verifier
type CertVerifier interface {
	// Verify checks whether the certificate is revoked.
	// The error is returned if:
	// - the certificate was revoked
	// - (for OCSP) the certificate is not known by OCSP server and we requested tls_ocsp_required == "denyUnknown" or "requireGood"
	// - (for OCSP) if we were unable to contact OCSP server(s) but we really need the response, tls_ocsp_required == "requireGood"
	Verify(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
}

// NewCertVerifier creates a CertVerifier based on passed OCSP and CRL command line flags.
// Ignores `--tls_{ocsp,crl}_{client,database}_url` flags, only uses `--tls_{ocsp,crl}_url` as URL source.
func NewCertVerifier() (CertVerifier, error) {
	ocspConfig, err := NewOCSPConfig(tlsOcspURL, tlsOcspRequired, tlsOcspFromCert, tlsOcspCheckOnlyLeafCertificate)
	if err != nil {
		return nil, err
	}

	crlConfig, err := NewCRLConfig(tlsCrlURL, tlsCrlFromCert, tlsCrlCheckOnlyLeafCertificate, tlsCrlCacheSize, tlsCrlCacheTime)
	if err != nil {
		return nil, err
	}

	return NewCertVerifierFromConfigs(ocspConfig, crlConfig)
}

// NewCertVerifierFromConfigs creates a CertVerifier based on passed OCSP and CRL configs
func NewCertVerifierFromConfigs(ocspConfig *OCSPConfig, crlConfig *CRLConfig) (CertVerifier, error) {
	certVerifier := NewCertVerifierAll()

	if ocspConfig.UseOCSP() {
		log.Debugln("NewCertVerifierFromConfigs(): adding OCSP verifier")
		ocspVerifier := DefaultOCSPVerifier{
			Config: *ocspConfig,
			Client: NewDefaultOCSPClient(),
		}
		certVerifier.Push(ocspVerifier)
	}

	if crlConfig.UseCRL() {
		log.Debugln("NewCertVerifierFromConfigs(): adding CRL verifier")
		crlVerifier := DefaultCRLVerifier{
			Config: *crlConfig,
			Client: NewDefaultCRLClient(),
			Cache:  NewLRUCRLCache(crlConfig.cacheSize),
		}
		certVerifier.Push(crlVerifier)
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
