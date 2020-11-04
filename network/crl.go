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
	Fetch(uri string) ([]byte, error)
}

type DefaultCRLClient struct{}

func (c DefaultCRLClient) Fetch(uri string) ([]byte, error) {
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

		return content, nil
	} else if strings.HasPrefix(uri, "file://") {
		content, err := ioutil.ReadFile(uri[7:])
		if err != nil {
			return nil, err
		}

		return content, nil
	}

	return nil, errors.New(fmt.Sprintf("Cannot fetch CRL from '%s', unsupported protocol", uri))
}

type CRLCache interface {
	Get(key string) ([]byte, error)
	Put(key string, value []byte) error
	Remove(key string) error
}

type DefaultCRLCache struct {
	cache sync.Map
}

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
	} else {
		log.Debugf("CRL: cache: '%s' not found", key)
		return nil, errors.New("Key not found")
	}
}

func (c *DefaultCRLCache) Put(key string, value []byte) error {
	c.cache.Store(key, value)
	log.Debugf("CRL: cache: inserted '%s'", key)
	return nil
}

func (c *DefaultCRLCache) Remove(key string) error {
	c.cache.Delete(key)
	log.Debugf("CRL: cache: removed '%s'", key)
	return nil
}

type CRLVerifier interface {
	// Verify returns number of confirmations (how many CRLs don't contain the certificate) or error.
	// The error is returned only if the certificate was revoked.
	Verify(chain []*x509.Certificate) (int, error)
}

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
		} else {
			return crl, nil
		}
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

func (v DefaultCRLVerifier) Verify(chain []*x509.Certificate) (int, error) {
	log.Debugf("CRL: Verifying '%s'", chain[0].Subject.CommonName)

	if len(v.Config.uri) == 0 && v.Config.fromCert == crlFromCertIgnore {
		log.Debugln("CRL: Skipping check since no config URI specified and we were told to ignore URIs from certificate")
		return 0, nil
	}

	cert := chain[0]
	issuer := chain[1]

	for i := range cert.CRLDistributionPoints {
		log.Debugf("CRL: certificate contains CRL URI: %s", cert.CRLDistributionPoints[i])
	}

	confirmsByConfigCRL := 0
	confirmsByCertCRL := 0

	// TODO avoid querying same CRL more than once, maybe create some list of checked CRLs (based on URI)

	for {
		if len(v.Config.uri) > 0 {
			rawCRL, err := v.getCachedOrFetch(v.Config.uri)
			if err != nil {
				log.WithError(err).Debugf("CRL: Cannot get CRL from '%s'", v.Config.uri)
				// XXX return error instead?
				break
			}

			crl, err := x509.ParseCRL(rawCRL)
			if err != nil {
				log.WithError(err).Debugf("CRL: Cannot parse CRL from '%s'", v.Config.uri)
				// XXX return error instead?
				break
			}

			err = issuer.CheckCRLSignature(crl)
			if err != nil {
				log.WithError(err).Warnf("CRL: Failed to check signature for CRL at %s", v.Config.uri)
				// XXX return error instead?
				break
			}

			for i := range crl.TBSCertList.RevokedCertificates {
				if crl.TBSCertList.RevokedCertificates[i].SerialNumber.Cmp(cert.SerialNumber) == 0 {
					log.Warnf("CRL: Certificate %v was revoked at %v", cert.SerialNumber, crl.TBSCertList.RevokedCertificates[i].RevocationTime)
					return 0, errors.New(fmt.Sprintf("Certificate %v was revoked at %v", cert.SerialNumber, crl.TBSCertList.RevokedCertificates[i].RevocationTime))
				}
			}

			confirmsByConfigCRL += 1
		}
		break
	}

	if len(cert.CRLDistributionPoints) > 0 {
		for i := range cert.CRLDistributionPoints {
			rawCRL, err := v.getCachedOrFetch(cert.CRLDistributionPoints[i])
			if err != nil {
				log.WithError(err).Debugf("CRL: Cannot get CRL from '%s'", cert.CRLDistributionPoints[i])
				// XXX return error instead?
				continue
			}

			crl, err := x509.ParseCRL(rawCRL)
			if err != nil {
				log.WithError(err).Debugf("CRL: Cannot parse CRL from '%s'", cert.CRLDistributionPoints[i])
				// XXX return error instead?
				continue
			}

			err = issuer.CheckCRLSignature(crl)
			if err != nil {
				log.WithError(err).Warnf("CRL: Failed to check signature for CRL at %s", cert.CRLDistributionPoints[i])
				// XXX return error instead?
				continue
			}

			if crl.TBSCertList.RevokedCertificates[i].SerialNumber.Cmp(cert.SerialNumber) == 0 {
				log.Warnf("CRL: Certificate %v was revoked at %v", cert.SerialNumber, crl.TBSCertList.RevokedCertificates[i].RevocationTime)
				return 0, errors.New(fmt.Sprintf("Certificate %v was revoked at %v", cert.SerialNumber, crl.TBSCertList.RevokedCertificates[i].RevocationTime))
			}
		}

		confirmsByCertCRL += 1
	}

	// XXX with cache containing raw CRL, we have to parse and verify signature on every check,
	//     maybe it's better to store parsed and verified CRL instead?

	return confirmsByConfigCRL + confirmsByCertCRL, nil
}
