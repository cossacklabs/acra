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
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net/http"
	url_ "net/url"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"

	"github.com/cossacklabs/acra/utils/args"
)

// Errors returned by OCSP verifier
var (
	ErrInvalidConfigOCSPRequired   = errors.New("invalid `ocsp_required` value")
	ErrInvalidConfigOCSPFromCert   = errors.New("invalid `ocsp_from_cert` value")
	ErrInvalidConfigAllRequiresURL = errors.New("when passing `--tls_ocsp_required=" + OcspRequiredGoodStr + "`, URL is mandatory")
	ErrOCSPRequiredAllButGotError  = errors.New("cannot query OCSP server, but --tls_ocsp_required=" + OcspRequiredGoodStr + " was passed")
	ErrOCSPUnknownCertificate      = errors.New("OCSP server doesn't know about certificate")
	ErrOCSPNoConfirms              = errors.New("none of OCSP servers confirmed the certificate")
)

// Possible values for flag `--tls_ocsp_required`
const (
	// Deny certificates now known by OCSP server(s)
	OcspRequiredDenyUnknownStr = "denyUnknown"
	// Allow certificates not known by OCSP server(s)
	OcspRequiredAllowUnknownStr = "allowUnknown"
	// Effect of denyUnknown + all available OCSP servers (the one from config
	// and those listed in certificate) should respond, otherwise deny the certificate
	OcspRequiredGoodStr = "requireGood"
)

// OcspRequiredValuesList contains all possible values for flag `--tls_ocsp_required`
var OcspRequiredValuesList = []string{
	OcspRequiredDenyUnknownStr,
	OcspRequiredAllowUnknownStr,
	OcspRequiredGoodStr,
}

var (
	ocspRequiredValValues = map[string]int{
		OcspRequiredDenyUnknownStr:  ocspRequiredDenyUnknown,
		OcspRequiredAllowUnknownStr: ocspRequiredAllowUnknown,
		OcspRequiredGoodStr:         ocspRequiredGood,
	}
)

const (
	ocspRequiredDenyUnknown int = iota
	ocspRequiredAllowUnknown
	ocspRequiredGood
)

// Possible values for flag `--tls_ocsp_from_cert`
const (
	// Use OCSP servers listed in certificate (if any), try them after the one
	// configured from CLI/config
	OcspFromCertUseStr = "use"
	// Query servers listed in certificate and don't perform further requests
	// if one respons with "ok, valid"
	OcspFromCertTrustStr = "trust"
	// Query servers listed in certificate before the one from config
	OcspFromCertPreferStr = "prefer"
	// Ignore OCSP servers listed in certificates
	OcspFromCertIgnoreStr = "ignore"
)

// OcspFromCertValuesList contains all possible values for flag `--tls_ocsp_from_cert`
var OcspFromCertValuesList = []string{
	OcspFromCertUseStr,
	OcspFromCertTrustStr,
	OcspFromCertPreferStr,
	OcspFromCertIgnoreStr,
}

var (
	ocspFromCertValValues = map[string]int{
		OcspFromCertUseStr:    ocspFromCertUse,
		OcspFromCertTrustStr:  ocspFromCertTrust,
		OcspFromCertPreferStr: ocspFromCertPrefer,
		OcspFromCertIgnoreStr: ocspFromCertIgnore,
	}
)

const (
	ocspFromCertUse int = iota
	ocspFromCertTrust
	ocspFromCertPrefer
	ocspFromCertIgnore
)

// OCSPConfig contains configuration related to certificate validation using OCSP
type OCSPConfig struct {
	url                      string
	required                 int // ocspRequired*
	fromCert                 int // ocspFromCert*
	checkOnlyLeafCertificate bool
	ClientAuthType           tls.ClientAuthType
}

const (
	// OcspHTTPClientDefaultTimeout is default timeout for HTTP client used to perform OCSP queries
	OcspHTTPClientDefaultTimeout = time.Second * time.Duration(15)
)

// NewOCSPConfigByName return initialized OCSPConfig config using flags registered with RegisterCertVerifierArgsForService
func NewOCSPConfigByName(extractor *args.ServiceExtractor, name string, namerFunc CLIParamNameConstructorFunc) (*OCSPConfig, error) {
	var (
		url               = extractor.GetString(namerFunc(name, "url", "ocsp"), "tls_ocsp_url")
		required          = extractor.GetString(namerFunc(name, "required", "ocsp"), "tls_ocsp_required")
		fromCert          = extractor.GetString(namerFunc(name, "from_cert", "ocsp"), "tls_ocsp_from_cert")
		checkOnlyLeafCert = extractor.GetBool(namerFunc(name, "check_only_leaf_certificate", "ocsp"), "tls_ocsp_check_only_leaf_certificate")
	)

	return NewOCSPConfig(url, required, fromCert, checkOnlyLeafCert)
}

// NewOCSPConfig creates new OCSPConfig
func NewOCSPConfig(url, required, fromCert string, checkOnlyLeafCertificate bool) (*OCSPConfig, error) {
	requiredVal, ok := ocspRequiredValValues[required]
	if !ok {
		return nil, ErrInvalidConfigOCSPRequired
	}

	fromCertVal, ok := ocspFromCertValValues[fromCert]
	if !ok {
		return nil, ErrInvalidConfigOCSPFromCert
	}

	if requiredVal == ocspRequiredGood && url == "" {
		return nil, ErrInvalidConfigAllRequiresURL
	}

	if url != "" {
		_, err := url_.Parse(url)
		if err != nil {
			return nil, err
		}

		log.Debugf("OCSP: Using server '%s'", url)

		httpClient := &http.Client{}
		_, err = httpClient.Head(url)
		if err != nil {
			log.WithError(err).WithField("url", url).Warnln("OCSP: Cannot reach configured server")
		}
	}

	switch requiredVal {
	case ocspRequiredDenyUnknown:
		log.Debugln("OCSP: At least one OCSP server should confirm certificate validity")
	case ocspRequiredAllowUnknown:
		log.Debugln("OCSP: Allowing certificates not known by OCSP server")
	case ocspRequiredGood:
		log.Debugln("OCSP: Requiring positive response from all OCSP servers")
	}

	switch fromCertVal {
	case ocspFromCertUse:
		log.Debugln("OCSP: using servers described in certificates if nothing passed via command line")
	case ocspFromCertTrust:
		log.Debugln("OCSP: trusting responses from OCSP servers listed in certificates")
	case ocspFromCertPrefer:
		log.Debugln("OCSP: server from certificate will be prioritized over one from command line")
	case ocspFromCertIgnore:
		log.Debugln("OCSP: ignoring OCSP servers described in certificates")
	}

	return &OCSPConfig{
		url:                      url,
		required:                 requiredVal,
		fromCert:                 fromCertVal,
		ClientAuthType:           tls.RequireAndVerifyClientCert,
		checkOnlyLeafCertificate: checkOnlyLeafCertificate,
	}, nil
}

// UseOCSP returns true if verification via OCSP is enabled
func (c *OCSPConfig) UseOCSP() bool {
	if c == nil {
		return false
	}
	return c.url != "" || c.fromCert != ocspFromCertIgnore
}

// OCSPClient is used to perform OCSP queries to some URL
type OCSPClient interface {
	// Query generates OCSP request about specified certificate, sends it to server and returns the response
	Query(commonName string, clientCert, issuerCert *x509.Certificate, ocspServerURL string) (*ocsp.Response, error)
}

// DefaultOCSPClient is a default implementation of OCSPClient
type DefaultOCSPClient struct {
	httpClient *http.Client
}

// NewDefaultOCSPClient creates new DefaultOCSPClient
func NewDefaultOCSPClient() DefaultOCSPClient {
	return DefaultOCSPClient{httpClient: &http.Client{
		Timeout: OcspHTTPClientDefaultTimeout,
	}}
}

// Query generates OCSP request about specified certificate, sends it to server and returns the response
func (c DefaultOCSPClient) Query(commonName string, clientCert, issuerCert *x509.Certificate, ocspServerURL string) (*ocsp.Response, error) {
	opts := &ocsp.RequestOptions{Hash: crypto.SHA256}
	buffer, err := ocsp.CreateRequest(clientCert, issuerCert, opts)
	if err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequest(http.MethodPost, ocspServerURL, bytes.NewBuffer(buffer))
	if err != nil {
		return nil, err
	}
	ocspURL, err := url_.Parse(ocspServerURL)
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspURL.Host)
	httpResponse, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer httpResponse.Body.Close()
	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}
	ocspResponse, err := ocsp.ParseResponseForCert(output, clientCert, issuerCert)
	return ocspResponse, err
}

// DefaultOCSPVerifier is a default OCSP verifier
type DefaultOCSPVerifier struct {
	Config OCSPConfig
	Client OCSPClient
}

// ocspServerToCheck is used to plan OCSP requests
type ocspServerToCheck struct {
	url      string
	fromCert bool
}

func (v DefaultOCSPVerifier) verifyCertWithIssuer(cert, issuer *x509.Certificate, useConfigURL bool) error {
	log.Debugf("OCSP: Verifying '%s'", cert.Subject.String())

	for _, ocspServer := range cert.OCSPServer {
		log.Debugf("OCSP: certificate contains OCSP URL: %s", ocspServer)
	}

	serversToCheck := []ocspServerToCheck{}

	if v.Config.fromCert != ocspFromCertIgnore {
		for _, ocspServer := range cert.OCSPServer {
			serverToCheck := ocspServerToCheck{url: ocspServer, fromCert: true}
			log.Debugf("OCSP: appending server %s, from cert", serverToCheck.url)
			serversToCheck = append(serversToCheck, serverToCheck)
		}
	} else if len(cert.OCSPServer) > 0 {
		log.Debugf("OCSP: Ignoring %d OCSP servers from certificate", len(cert.OCSPServer))
	}

	if v.Config.url != "" && useConfigURL {
		serverToCheck := ocspServerToCheck{url: v.Config.url, fromCert: false}

		if v.Config.fromCert == ocspFromCertPrefer || v.Config.fromCert == ocspFromCertTrust {
			log.Debugf("OCSP: appending server %s, from config", serverToCheck.url)
			serversToCheck = append(serversToCheck, serverToCheck)
		} else {
			log.Debugf("OCSP: prepending server %s, from config", serverToCheck.url)
			serversToCheck = append([]ocspServerToCheck{serverToCheck}, serversToCheck...)
		}
	}

	queriedOCSPs := make(map[string]struct{})

	confirms := 0

	for _, serverToCheck := range serversToCheck {
		log.Debugf("OCSP: Trying server %s", serverToCheck.url)

		if _, ok := queriedOCSPs[serverToCheck.url]; ok {
			log.Debugln("OCSP: Skipping, already queried")
			continue
		}

		response, err := v.Client.Query(cert.Issuer.CommonName, cert, issuer, serverToCheck.url)
		if err != nil {
			log.WithError(err).WithField("url", serverToCheck.url).Warnln("Cannot query OCSP server")
			log.WithError(err).WithField("url", serverToCheck.url).
				Infoln(OCSPCheckErrorSuggestion)

			if v.Config.required == ocspRequiredGood {
				return ErrOCSPRequiredAllButGotError
			}

			continue
		}

		switch response.Status {
		case ocsp.Good:
			confirms++

			if serverToCheck.fromCert {
				log.Debugln("OCSP: confirmed by server from certificate")
			} else {
				log.Debugln("OCSP: confirmed by server from config")
			}

			if v.Config.required != ocspRequiredGood {
				// One confirmation is enough if we don't require all OCSP servers to confirm the certificate validity
				break
			}

			if serverToCheck.fromCert && v.Config.fromCert == ocspFromCertTrust {
				// If this OCSP server came from certificate and `--tls_ocsp_from_cert=trust`, don't perform further checks
				break
			}
		case ocsp.Revoked:
			// If any OCSP server replies with "certificate was revoked", return error immediately
			log.WithField("serial", cert.SerialNumber.Text(16)).WithField("revoked_at", response.RevokedAt).Warnln("OCSP: Certificate was revoked")
			return ErrCertWasRevoked
		case ocsp.Unknown:
			// Treat "Unknown" response as error if tls_ocsp_required is "yes" or "all"
			if v.Config.required != ocspRequiredAllowUnknown {
				log.WithField("url", serverToCheck.url).WithField("serial", cert.SerialNumber.Text(16)).Warnln("OCSP server doesn't know about certificate")
				return ErrOCSPUnknownCertificate
			}
		}

		queriedOCSPs[serverToCheck.url] = struct{}{}
	}

	if len(serversToCheck) > 0 && confirms == 0 {
		return ErrOCSPNoConfirms
	}
	return nil
}

// Verify ensures certificate is not revoked by querying configured OCSP servers
func (v DefaultOCSPVerifier) Verify(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	for _, chain := range verifiedChains {
		if len(chain) == 0 {
			switch v.Config.ClientAuthType {
			case tls.NoClientCert, tls.RequestClientCert, tls.RequireAnyClientCert:
				log.Infoln("OCSP: Empty verified certificates chain, nothing to do")
				return nil
			default: // tls.VerifyClientCertIfGiven, tls.RequireAndVerifyClientCert
				return ErrEmptyCertChain
			}
		}

		if len(chain) == 1 {
			log.WithField("serial", chain[0].SerialNumber).
				Warnln("OCSP: Certificate chain consists of one root certificate, it is recommended to use dedicated non-root certificates for TLS handshake")
			return v.verifyCertWithIssuer(chain[0], chain[0], false)
		}

		for i := 0; i < len(chain)-1; i++ {
			cert := chain[i]
			issuer := chain[i+1]

			// 3rd argument, useConfigURL, whether to use OCSP server URL from configuration (if set),
			// don't use it for other certificates except end one (i.e. don't use it when checking intermediate
			// certificates because v.Config.checkOnlyLeafCertificate == false)
			err := v.verifyCertWithIssuer(cert, issuer, i == 0)
			if err != nil {
				return err
			}

			if v.Config.checkOnlyLeafCertificate {
				break
			}
		}
	}

	return nil
}
