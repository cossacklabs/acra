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
	log "github.com/sirupsen/logrus"
	"net/url"
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

	return &CRLConfig{uri: uri, fromCert: fromCertVal}, nil
}

func checkCRL(chain []*x509.Certificate, config *CRLConfig) (int, error) {
	log.Infof("CRL: checkCRL() > CN = %s", chain[0].Subject.CommonName)

	return 0, nil
}
