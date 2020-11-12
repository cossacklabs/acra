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
	"crypto/x509"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
	"net/url"
)

// --tls_ocsp_required=<denyUnknown|allowUnknown|all>
const (
	// Deny certificates now known by OCSP server(s)
	ocspRequiredYesStr = "denyUnknown"
	// Allow certificates now known by OCSP server(s)
	ocspRequiredNoStr = "allowUnknown"
	// Effect of denyUnknown + all available OCSP servers (the one from config
	// and those listed in certificate) should respond, otherwise deny the certificate
	ocspRequiredAllStr = "all"
)

const (
	ocspRequiredYes int = iota
	ocspRequiredNo
	ocspRequiredAll
)

// --tls_ocsp_from_cert=<use|trust|prefer|ignore>
const (
	// Use OCSP servers listed in certificate (if any), try them after the one
	// configured from CLI/config
	ocspFromCertUseStr = "use"
	// Query servers listed in certificate and don't perform further requests
	// if one respons with "ok, valid"
	ocspFromCertTrustStr = "trust"
	// Query servers listed in certificate before the one from config
	ocspFromCertPreferStr = "prefer"
	// Ignore OCSP servers listed in certificates
	ocspFromCertIgnoreStr = "ignore"
)

const (
	ocspFromCertUse int = iota
	ocspFromCertTrust
	ocspFromCertPrefer
	ocspFromCertIgnore
)

// OCSPConfig contains configuration related to certificate validation using OCSP
type OCSPConfig struct {
	url      string
	required int // ocspRequired*
	fromCert int // ocspFromCert*
}

// NewOCSPConfig creates new OCSPConfig
func NewOCSPConfig(uri, required, fromCert string) (*OCSPConfig, error) {
	if uri != "" {
		_, err := url.Parse(uri)
		if err != nil {
			return nil, err
		}

		// TODO: Do some request to `uri`, log warn if failed
	}

	var requiredVal int
	switch required {
	case ocspRequiredYesStr:
		requiredVal = ocspRequiredYes
	case ocspRequiredNoStr:
		requiredVal = ocspRequiredNo
	case ocspRequiredAllStr:
		requiredVal = ocspRequiredAll
	default:
		return nil, errors.New("Invalid `ocsp_required` value '" + required + "', should be one of 'yes', 'no', 'all'")
	}

	var fromCertVal int
	switch fromCert {
	case ocspFromCertUseStr:
		fromCertVal = ocspFromCertUse
	case ocspFromCertTrustStr:
		fromCertVal = ocspFromCertTrust
	case ocspFromCertPreferStr:
		fromCertVal = ocspFromCertPrefer
	case ocspFromCertIgnoreStr:
		fromCertVal = ocspFromCertIgnore
	default:
		return nil, errors.New("Invalid `ocsp_from_cert` value '" + fromCert + "', should be one of 'use', 'trust', 'prefer', 'ignore'")
	}

	if uri != "" {
		log.Debugf("OCSP: Using server '%s'", uri)
	}

	switch required {
	case "yes", "true":
		log.Debugf("OCSP: At least one OCSP server should confirm certificate validity")
	case "no", "false":
		log.Debugf("OCSP: Allowing certificates not known by OCSP server")
	case "all":
		log.Debugf("OCSP: Requiring positive response from all OCSP servers")
	}

	switch fromCert {
	case "use":
		log.Debugf("OCSP: using servers described in certificates if nothing passed via command line")
	case "trust":
		log.Debugf("OCSP: trusting responses from OCSP servers listed in certificates")
	case "prefer":
		log.Debugf("OCSP: server from certificate will be prioritized over one from command line")
	case "ignore":
		log.Debugf("OCSP: ignoring OCSP servers described in certificates")
	}

	return &OCSPConfig{url: uri, required: requiredVal, fromCert: fromCertVal}, nil
}

// OCSPClient is used to perform OCSP queries to some URI
type OCSPClient interface {
	// Query generates OCSP request about specified certificate, sends it to server and returns the response
	Query(commonName string, clientCert, issuerCert *x509.Certificate, ocspServerURL string) (*ocsp.Response, error)
}

// DefaultOCSPClient is a default implementation of OCSPClient
type DefaultOCSPClient struct{}

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
	ocspURL, err := url.Parse(ocspServerURL)
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspURL.Host)
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer httpResponse.Body.Close()
	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}
	ocspResponse, err := ocsp.ParseResponse(output, issuerCert)
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

// Verify ensures certificate is not revoked by querying configured OCSP servers
func (v DefaultOCSPVerifier) Verify(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	for _, chain := range verifiedChains {
		log.Debugf("OCSP: Verifying '%s'", chain[0].Subject.String())

		cert := chain[0]
		issuer := chain[1]

		for _, ocspServer := range cert.OCSPServer {
			log.Debugf("OCSP: certificate contains OCSP URI: %s", ocspServer)
		}

		serversToCheck := []ocspServerToCheck{}

		if v.Config.fromCert != ocspFromCertIgnore {
			for _, ocspServer := range cert.OCSPServer {
				serverToCheck := ocspServerToCheck{url: ocspServer, fromCert: true}
				log.Debugf("OCSP: appending server %s, from cert", serverToCheck.url)
				serversToCheck = append(serversToCheck, serverToCheck)
			}
		} else {
			if len(cert.OCSPServer) > 0 {
				log.Debugf("OCSP: Ignoring %d OCSP servers from certificate", len(cert.OCSPServer))
			}
		}

		if v.Config.url != "" {
			serverToCheck := ocspServerToCheck{url: v.Config.url, fromCert: false}

			if v.Config.fromCert == ocspFromCertPrefer || v.Config.fromCert == ocspFromCertTrust {
				log.Debugf("OCSP: appending server %s, from config", serverToCheck.url)
				serversToCheck = append(serversToCheck, serverToCheck)
			} else {
				log.Debugf("OCSP: prepending server %s, from config", serverToCheck.url)
				serversToCheck = append([]ocspServerToCheck{serverToCheck}, serversToCheck...)
			}
		}

		// TODO avoid querying same OCSP more than once

		for _, serverToCheck := range serversToCheck {
			log.Debugf("OCSP: Trying server %s", serverToCheck.url)

			response, err := v.Client.Query(cert.Issuer.CommonName, cert, issuer, serverToCheck.url)
			if err != nil {
				log.WithError(err).Warnf("Cannot query OCSP server at %s", serverToCheck.url)

				if v.Config.required == ocspRequiredAll {
					return errors.New("Cannot query OCSP server, but --tls_ocsp_required=all was passed")
				}

				continue
			}

			switch response.Status {
			case ocsp.Good:
				if serverToCheck.fromCert {
					log.Debugln("OCSP: confirmed by server from certificate")
				} else {
					log.Debugln("OCSP: confirmed by server from config")
				}

				if v.Config.required != ocspRequiredAll {
					// One confirmation is enough if we don't require all OCSP servers to confirm the certificate validity
					break
				}
			case ocsp.Revoked:
				// If any OCSP server replies with "certificate was revoked", return error immediately
				return fmt.Errorf("Certificate 0x%s was revoked", cert.SerialNumber.Text(16))
			case ocsp.Unknown:
				// Treat "Unknown" response as error if tls_ocsp_required is "yes" or "all"
				if v.Config.required != ocspRequiredNo {
					return fmt.Errorf("OCSP server %s doesn't know about certificate 0x%s", serverToCheck.url, cert.SerialNumber.Text(16))
				}
			}
		}
	}

	return nil
}
