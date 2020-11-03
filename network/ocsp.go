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

const (
	ocspRequiredYes int = iota
	ocspRequiredNo
	ocspRequiredAll
)

const (
	ocspFromCertUse int = iota
	ocspFromCertTrust
	ocspFromCertPrefer
	ocspFromCertIgnore
)

type OCSPConfig struct {
	url      string
	required int // ocspRequired*
	fromCert int // ocspFromCert*
}

func NewOCSPConfig(uri, required, fromCert string) (*OCSPConfig, error) {
	if len(uri) > 0 {
		_, err := url.Parse(uri)
		if err != nil {
			return nil, err
		}

		// TODO: Do some request to `uri`, log warn if failed
	}

	var requiredVal int
	switch required {
	case "yes", "true":
		requiredVal = ocspRequiredYes
	case "no", "false":
		requiredVal = ocspRequiredNo
	case "all":
		requiredVal = ocspRequiredAll
	default:
		return nil, errors.New("Invalid `ocsp_required` value '" + required + "', should be one of 'yes', 'no', 'all'")
	}

	var fromCertVal int
	switch fromCert {
	case "use":
		fromCertVal = ocspFromCertUse
	case "trust":
		fromCertVal = ocspFromCertTrust
	case "prefer":
		fromCertVal = ocspFromCertPrefer
	case "ignore":
		fromCertVal = ocspFromCertIgnore
	default:
		return nil, errors.New("Invalid `ocsp_from_cert` value '" + fromCert + "', should be one of 'use', 'trust', 'prefer', 'ignore'")
	}

	if len(uri) > 0 {
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

func (c *OCSPConfig) Describe() string {
	return fmt.Sprintf("url=%s, required=%d, fromCert=%d", c.url, c.required, c.fromCert)
}

type OCSPClient interface {
	// Query generates OCSP request about specified certificate, sends it to server and returns the response
	Query(commonName string, clientCert, issuerCert *x509.Certificate, ocspServerUrl string) (*ocsp.Response, error)
}

type DefaultOCSPClient struct{}

func (c DefaultOCSPClient) Query(commonName string, clientCert, issuerCert *x509.Certificate, ocspServerUrl string) (*ocsp.Response, error) {
	opts := &ocsp.RequestOptions{Hash: crypto.SHA256}
	buffer, err := ocsp.CreateRequest(clientCert, issuerCert, opts)
	if err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequest(http.MethodPost, ocspServerUrl, bytes.NewBuffer(buffer))
	if err != nil {
		return nil, err
	}
	ocspUrl, err := url.Parse(ocspServerUrl)
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspUrl.Host)
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

type OCSPVerifier interface {
	// Verify returns number of confirmations or error.
	// The error is returned only if it is critical, for example:
	// - the certificate was revoked
	// - the certificate is not known by OCSP server and we requested tls_ocsp_required == "yes" or "all"
	// - if we were unable to contact OCSP server(s) but we really need the response, tls_ocsp_required == "all"
	Verify(chain []*x509.Certificate) (int, error)
}

type DefaultOCSPVerifier struct {
	Config OCSPConfig
	Client OCSPClient
}

// ocspServerToCheck is used to plan OCSP requests
type ocspServerToCheck struct {
	url      string
	fromCert bool
}

func (v DefaultOCSPVerifier) Verify(chain []*x509.Certificate) (int, error) {
	log.Infof("OCSP: Verify( %s )", chain[0].Subject.CommonName)

	cert := chain[0]
	issuer := chain[1]

	serversToCheck := []ocspServerToCheck{}

	if v.Config.fromCert != ocspFromCertIgnore {
		for i := range cert.OCSPServer {
			serverToCheck := ocspServerToCheck{url: cert.OCSPServer[i], fromCert: true}
			log.Debugf("OCSP: appending server %s, from cert", serverToCheck.url)
			serversToCheck = append(serversToCheck, serverToCheck)
		}
	} else {
		if len(cert.OCSPServer) > 0 {
			log.Debugf("OCSP: Ignoring %d OCSP servers from certificate", len(cert.OCSPServer))
		}
	}

	if len(v.Config.url) > 0 {
		serverToCheck := ocspServerToCheck{url: v.Config.url, fromCert: false}

		if v.Config.fromCert == ocspFromCertPrefer || v.Config.fromCert == ocspFromCertTrust {
			log.Debugf("OCSP: appending server %s, from config", serverToCheck.url)
			serversToCheck = append(serversToCheck, serverToCheck)
		} else {
			log.Debugf("OCSP: prepending server %s, from config", serverToCheck.url)
			serversToCheck = append([]ocspServerToCheck{serverToCheck}, serversToCheck...)
		}
	}

	confirmsByConfigOCSP := 0
	confirmsByCertOCSP := 0

	for i := range serversToCheck {
		log.Debugf("OCSP: Trying server %s", serversToCheck[i].url)

		response, err := v.Client.Query(cert.Issuer.CommonName, cert, issuer, serversToCheck[i].url)
		if err != nil {
			_ = response
			log.WithError(err).Warnf("Cannot query OCSP server at %s", serversToCheck[i])

			if v.Config.required == ocspRequiredAll {
				return 0, errors.New("Cannot query OCSP server, but --tls_ocsp_required=all was passed")
			}

			continue
		}

		switch response.Status {
		case ocsp.Good:
			if serversToCheck[i].fromCert {
				confirmsByCertOCSP += 1
			} else {
				confirmsByConfigOCSP += 1
			}

			if v.Config.required != ocspRequiredAll {
				// One confirmation is enough if we don't require all OCSP servers to confirm the certificate validity
				break
			}
		case ocsp.Revoked:
			// If any OCSP server replies with "certificate was revoked", return error immediately
			return 0, errors.New(fmt.Sprintf("Certificate 0x%s was revoked", cert.SerialNumber.Text(16)))
		case ocsp.Unknown:
			// Treat "Unknown" response as error if tls_ocsp_required is "yes" or "all"
			if v.Config.required != ocspRequiredNo {
				return 0, errors.New(fmt.Sprintf("OCSP server %s doesn't know about certificate 0x%s", serversToCheck[i].url, cert.SerialNumber.Text(16)))
			}
		}
	}

	return confirmsByConfigOCSP + confirmsByCertOCSP, nil
}
