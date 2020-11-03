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
	"crypto/x509/pkix"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const (
	crlFromCertUse int = iota
	crlFromCertIgnore
)

type CRLConfig struct {
	uri      string
	fromCert int // crlFromCert*
}

func NewCRLConfig(uri, fromCert string) (*CRLConfig, error) {
	_, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	var fromCertVal int
	switch fromCert {
	case "use":
		fromCertVal = crlFromCertUse
	case "ignore":
		fromCertVal = crlFromCertIgnore
	default:
		return nil, errors.New("Invalid `tls_crl_from_cert` value '" + fromCert + "', should be one of 'use', 'ignore'")
	}
	// TODO: Download CRL from `uri`, log error if failed

	return &CRLConfig{uri: uri, fromCert: fromCertVal}, nil
}

type CRLClient interface {
	// Fetch fetches and parses CRL from passed URI (can be either http:// or file://)
	Fetch(uri string) (*pkix.CertificateList, error)
}

type DefaultCRLClient struct{}

func (c DefaultCRLClient) Fetch(uri string) (*pkix.CertificateList, error) {
	if strings.HasPrefix(uri, "http://") {
		httpRequest, err := http.NewRequest(http.MethodGet, uri, nil)
		if err != nil {
			return nil, err
		}
		ocspUrl, err := url.Parse(uri)
		if err != nil {
			return nil, err
		}
		httpRequest.Header.Add("Accept", "application/pkix-crl, application/pem-certificate-chain")
		httpRequest.Header.Add("host", ocspUrl.Host)
		httpClient := &http.Client{}
		httpResponse, err := httpClient.Do(httpRequest)
		if err != nil {
			return nil, err
		}
		defer httpResponse.Body.Close()
		content, err := ioutil.ReadAll(httpResponse.Body)
		if err != nil {
			return nil, err
		}

		crl, err := x509.ParseCRL(content)
		if err != nil {
			return nil, err
		}

		return crl, nil
	} else if strings.HasPrefix(uri, "file://") {
		content, err := ioutil.ReadFile(uri[7:])
		if err != nil {
			return nil, err
		}

		crl, err := x509.ParseCRL(content)
		if err != nil {
			return nil, err
		}

		return crl, nil
	}

	return nil, errors.New(fmt.Sprintf("Cannot fetch CRL from '%s', unsupported protocol", uri))
}

type CRLVerifier interface {
	// Verify returns number of confirmations (how many CRLs don't contain the certificate) or error.
	// The error is returned only if the certificate was revoked.
	Verify(chain []*x509.Certificate) (int, error)
}

type DefaultCRLVerifier struct {
	Config CRLConfig
	Client CRLClient
	// key = URI of cached CRL
	// value = parsed CRL
	// XXX maybe hide it behind mutex?
	cache map[string]*pkix.CertificateList
}

func (v DefaultCRLVerifier) Verify(chain []*x509.Certificate) (int, error) {
	if len(v.Config.uri) == 0 && v.Config.fromCert == crlFromCertIgnore {
		return 0, nil
	}

	log.Infof("CRL: Verify( %s )", chain[0].Subject.CommonName)

	// panic("not implemented")
	return 0, nil
}
