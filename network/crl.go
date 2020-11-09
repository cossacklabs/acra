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
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const (
	crlFromCertUse int = iota
	crlFromCertIgnore
)

// CRLConfig contains configuration related to certificate validation using CRL
type CRLConfig struct {
	uri      string
	fromCert int // crlFromCert*
}

// NewCRLConfig creates new CRLConfig
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

// CRLClient is used to fetch CRL from some URI
type CRLClient interface {
	// Fetch fetches CRL from passed URI (can be either http:// or file://)
	Fetch(uri string) ([]byte, error)
}

// DefaultCRLClient is a default implementation of CRLClient
// (as opposed to stub ones used in tests)
type DefaultCRLClient struct{}

// Fetch fetches CRL from passed URI (can be either http:// or file://)
func (c DefaultCRLClient) Fetch(uri string) ([]byte, error) {
	if strings.HasPrefix(uri, "http://") {
		httpRequest, err := http.NewRequest(http.MethodGet, uri, nil)
		if err != nil {
			return nil, err
		}
		crlURL, err := url.Parse(uri)
		if err != nil {
			return nil, err
		}
		httpRequest.Header.Add("Accept", "application/pkix-crl, application/pem-certificate-chain")
		httpRequest.Header.Add("host", crlURL.Host)
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

		return content, nil
	} else if strings.HasPrefix(uri, "file://") {
		content, err := ioutil.ReadFile(uri[7:])
		if err != nil {
			return nil, err
		}

		return content, nil
	}

	return nil, fmt.Errorf("Cannot fetch CRL from '%s', unsupported protocol", uri)
}

// CRLCache is used to store fetched CRLs to avoid downloading the same URI more than once
type CRLCache interface {
	Get(key string) ([]byte, error)
	Put(key string, value []byte) error
	Remove(key string) error
}

// DefaultCRLCache is a default implementation of CRLCache, internally stores items in sync.Map
type DefaultCRLCache struct {
	cache sync.Map
}

// Get tries to get CRL from cache, returns error if failed
func (c *DefaultCRLCache) Get(key string) ([]byte, error) {
	log.Debugf("CRL: cache: loading '%s'", key)
	value, ok := c.cache.Load(key)
	if ok {
		value, ok := value.([]byte)
		if !ok {
			// should never happen since Put() only inserts []byte
			return nil, errors.New("Unexpected value of invalid type")
		}
		log.Debugf("CRL: cache: '%s' found", key)
		return value, nil
	}

	log.Debugf("CRL: cache: '%s' not found", key)
	return nil, errors.New("Key not found")
}

// Put stores CRL in cache
func (c *DefaultCRLCache) Put(key string, value []byte) error {
	c.cache.Store(key, value)
	log.Debugf("CRL: cache: inserted '%s'", key)
	return nil
}

// Remove removes item from cache
func (c *DefaultCRLCache) Remove(key string) error {
	c.cache.Delete(key)
	log.Debugf("CRL: cache: removed '%s'", key)
	return nil
}

// CRLVerifier is used to implement different certificate verifiers that internally use CRLs
type CRLVerifier interface {
	// Verify returns number of confirmations (how many CRLs don't contain the certificate) or error.
	// The error is returned only if the certificate was revoked.
	Verify(chain []*x509.Certificate) (int, error)
}

// DefaultCRLVerifier is a default implementation of CRLVerifier
type DefaultCRLVerifier struct {
	Config CRLConfig
	Client CRLClient
	Cache  CRLCache
}

func (v DefaultCRLVerifier) getCachedOrFetch(uri string) ([]byte, error) {
	crl, err := v.Cache.Get(v.Config.uri)
	if crl != nil {
		if err != nil {
			return nil, err
		}

		return crl, nil
	}

	crl, err = v.Client.Fetch(uri)
	if crl != nil {
		err := v.Cache.Put(uri, crl)
		if err != nil {
			log.WithError(err).Warnf("Unable to store fetched '%s' in CRL cache", uri)
		}

		// TODO spawn goroutine to refresh CRL after some time,
		//      using crl.TBSCertList.NextUpdate is probably a good idea

		return crl, nil
	}

	return nil, err
}

// Verify ensures configured CRLs do not contain certificate from passed chain
func (v DefaultCRLVerifier) Verify(chain []*x509.Certificate) (int, error) {
	log.Debugf("CRL: Verifying '%s'", chain[0].Subject.CommonName)

	if len(v.Config.uri) == 0 && v.Config.fromCert == crlFromCertIgnore {
		log.Debugln("CRL: Skipping check since no config URI specified and we were told to ignore URIs from certificate")
		return 0, nil
	}

	cert := chain[0]
	issuer := chain[1]

	for _, crlDistributionPoint := range cert.CRLDistributionPoints {
		log.Debugf("CRL: certificate contains CRL URI: %s", crlDistributionPoint)
	}

	confirmsByConfigCRL := 0
	confirmsByCertCRL := 0

	// TODO avoid querying same CRL more than once, maybe create some list of checked CRLs (based on URI)

	for {
		if v.Config.uri != "" {
			rawCRL, err := v.getCachedOrFetch(v.Config.uri)
			if err != nil {
				log.WithError(err).Debugf("CRL: Cannot get CRL from '%s'", v.Config.uri)
				break // temporary
				// return 0, err
			}

			crl, err := x509.ParseCRL(rawCRL)
			if err != nil {
				log.WithError(err).Debugf("CRL: Cannot parse CRL from '%s'", v.Config.uri)
				return 0, err
			}

			err = issuer.CheckCRLSignature(crl)
			if err != nil {
				log.WithError(err).Warnf("CRL: Failed to check signature for CRL at %s", v.Config.uri)
				return 0, err
			}

			for _, revokedCertificate := range crl.TBSCertList.RevokedCertificates {
				if revokedCertificate.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					log.Warnf("CRL: Certificate %v was revoked at %v", cert.SerialNumber, revokedCertificate.RevocationTime)
					return 0, fmt.Errorf("Certificate %v was revoked at %v", cert.SerialNumber, revokedCertificate.RevocationTime)
				}
			}

			confirmsByConfigCRL++
		}
		break
	}

	if len(cert.CRLDistributionPoints) > 0 {
		for _, crlDistributionPoint := range cert.CRLDistributionPoints {
			rawCRL, err := v.getCachedOrFetch(crlDistributionPoint)
			if err != nil {
				log.WithError(err).Debugf("CRL: Cannot get CRL from '%s'", crlDistributionPoint)
				continue // temporary
				// return 0, err
			}

			crl, err := x509.ParseCRL(rawCRL)
			if err != nil {
				log.WithError(err).Debugf("CRL: Cannot parse CRL from '%s'", crlDistributionPoint)
				return 0, err
			}

			err = issuer.CheckCRLSignature(crl)
			if err != nil {
				log.WithError(err).Warnf("CRL: Failed to check signature for CRL at %s", crlDistributionPoint)
				return 0, err
			}

			for _, revokedCertificate := range crl.TBSCertList.RevokedCertificates {
				if revokedCertificate.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					log.Warnf("CRL: Certificate %v was revoked at %v", cert.SerialNumber, revokedCertificate.RevocationTime)
					return 0, fmt.Errorf("Certificate %v was revoked at %v", cert.SerialNumber, revokedCertificate.RevocationTime)
				}
			}
		}

		confirmsByCertCRL++
	}

	// XXX with cache containing raw CRL, we have to parse and verify signature on every check,
	//     maybe it's better to store parsed and verified CRL instead?

	return confirmsByConfigCRL + confirmsByCertCRL, nil
}
