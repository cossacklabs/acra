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
	// TODO: Download CRL from `uri`, log error if failed

	return &CRLConfig{uri: uri, fromCert: fromCertVal}, nil
}

type CRLVerifier interface {
	// Verify returns number of confirmations (how many CRLs don't contain the certificate) or error.
	// The error is returned only if the certificate was revoked.
	Verify(chain []*x509.Certificate) (int, error)
}

type DefaultCRLVerifier struct {
	Config CRLConfig
}

func (v DefaultCRLVerifier) Verify(chain []*x509.Certificate) (int, error) {
	if len(v.Config.uri) == 0 && v.Config.fromCert == crlFromCertIgnore {
		return 0, nil
	}

	log.Infof("CRL: Verify( %s )", chain[0].Subject.CommonName)

	return 0, nil
}
