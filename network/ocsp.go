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

func isCertificateRevokedByOCSP(commonName string, clientCert, issuerCert *x509.Certificate, ocspServer string) (bool, error) {
	opts := &ocsp.RequestOptions{Hash: crypto.SHA256}
	buffer, err := ocsp.CreateRequest(clientCert, issuerCert, opts)
	if err != nil {
		return false, err
	}
	httpRequest, err := http.NewRequest(http.MethodPost, ocspServer, bytes.NewBuffer(buffer))
	if err != nil {
		return false, err
	}
	ocspUrl, err := url.Parse(ocspServer)
	if err != nil {
		return false, err
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspUrl.Host)
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return false, err
	}
	defer httpResponse.Body.Close()
	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return false, err
	}
	ocspResponse, err := ocsp.ParseResponse(output, issuerCert)
	if err != nil {
		return false, err
	}
	if ocspResponse.Status == ocsp.Revoked {
		return true, nil
	} else {
		return false, nil
	}
}
