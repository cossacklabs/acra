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
	"sync"

	"github.com/golang/groupcache/lru"
)

// --tls_crl_from_cert=<use|ignore>
const (
	// If certificate contains CRL distribution point(s), use them
	crlFromCertUseStr = "use"
	// Ignore CRL distribution points listed in certificate
	crlFromCertIgnoreStr = "ignore"
)

const (
	crlFromCertUse int = iota
	crlFromCertIgnore
)

// CRLConfig contains configuration related to certificate validation using CRL
type CRLConfig struct {
	uri       string
	fromCert  int // crlFromCert*
	cacheSize int
}

// NewCRLConfig creates new CRLConfig
func NewCRLConfig(uri, fromCert string, cacheSize int) (*CRLConfig, error) {
	_, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	fromCertValValues := map[string]int{
		crlFromCertUseStr:    crlFromCertUse,
		crlFromCertIgnoreStr: crlFromCertIgnore,
	}

	fromCertVal, ok := fromCertValValues[fromCert]
	if !ok {
		return nil, errors.New("Invalid `tls_crl_from_cert` value '" + fromCert + "'")
	}

	if uri != "" {
		// Since this is CRL configuration alone, we don't have access to cache yet;
		// so let's just download the CRL and forget about it
		crlClient := NewDefaultCRLClient()
		_, err = crlClient.Fetch(uri)
		if err != nil {
			log.WithError(err).Warnf("CRL: Cannot fetch configured URI '%s'", uri)
			// TODO return error after issues with failing tests are fixed
			// return nil, fmt.Errorf("CRL: Cannot fetch configured URI '%s'", uri)
		}
	}

	return &CRLConfig{uri: uri, fromCert: fromCertVal}, nil
}

// CRLClient is used to fetch CRL from some URI
type CRLClient interface {
	// Fetch fetches CRL from passed URI (can be either http:// or file://)
	Fetch(uri string) ([]byte, error)
}

// DefaultCRLClient is a default implementation of CRLClient
// (as opposed to stub ones used in tests)
type DefaultCRLClient struct {
	httpClient *http.Client
}

func NewDefaultCRLClient() DefaultCRLClient {
	return DefaultCRLClient{httpClient: &http.Client{}}
}

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
		httpResponse, err := c.httpClient.Do(httpRequest)
		if err != nil {
			return nil, err
		}
		defer httpResponse.Body.Close()
		content, err := ioutil.ReadAll(httpResponse.Body)
		if err != nil {
			return nil, err
		}

		if httpResponse.StatusCode != 200 {
			return nil, fmt.Errorf("Server returned non-OK status: %s", httpResponse.Status)
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

// ParsedCRLCache is used to store fetched CRLs to avoid downloading the same URI more than once,
// stores parsed and verified CRLs
type ParsedCRLCache interface {
	Get(key string) (*pkix.CertificateList, error)
	Put(key string, value *pkix.CertificateList) error
	Remove(key string) error
}

// PRLRUParsedCRLCache is an implementation of ParsedCRLCache that uses LRU cache inside
type LRUParsedCRLCache struct {
	cache lru.Cache
	mutex sync.RWMutex
}

// NewLRUParsedCRLCache creates new LRUParsedCRLCache, able to store at most maxEntries values
func NewLRUParsedCRLCache(maxEntries int) *LRUParsedCRLCache {
	return &LRUParsedCRLCache{cache: lru.Cache{MaxEntries: maxEntries}}
}

// Get tries to get CRL from cache, returns error if failed
func (c *LRUParsedCRLCache) Get(key string) (*pkix.CertificateList, error) {
	log.Debugf("CRL: LRU cache: loading '%s'", key)
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	value, ok := c.cache.Get(key)
	if ok {
		value, ok := value.(*pkix.CertificateList)
		if !ok {
			// should never happen since Put() only inserts *pkix.CertificateList
			return nil, errors.New("Unexpected value of invalid type")
		}
		log.Debugf("CRL: LRU cache: '%s' found", key)
		return value, nil
	}

	return nil, errors.New("Key not found")
}

// Put stores CRL in cache
func (c *LRUParsedCRLCache) Put(key string, value *pkix.CertificateList) error {
	c.mutex.Lock()
	c.cache.Add(key, value)
	c.mutex.Unlock()
	log.Debugf("CRL: LRU cache: inserted '%s'", key)
	return nil
}

// Remove removes item from cache
func (c *LRUParsedCRLCache) Remove(key string) error {
	c.mutex.Lock()
	c.cache.Remove(key)
	c.mutex.Unlock()
	log.Debugf("CRL: LRU cache: removed '%s'", key)
	return nil
}

// DefaultCRLVerifier is a default implementation of CRLVerifier
type DefaultCRLVerifier struct {
	Config      CRLConfig
	Client      CRLClient
	ParsedCache ParsedCRLCache
}

// Tries to find cached CRL, fetches using v.Client if not found, checks the signature of CRL using issuerCert
func (v DefaultCRLVerifier) getCachedOrFetch(uri string, issuerCert *x509.Certificate) (*pkix.CertificateList, error) {
	// Try v.ParsedCache first
	crl, err := v.ParsedCache.Get(v.Config.uri)
	if crl != nil {
		if err != nil {
			// non-empty result + error, should never happen
			return nil, err
		}

		return crl, nil
	}

	// Not found in cache, gotta fetch
	rawCRL, err := v.Client.Fetch(uri)
	if err != nil {
		return nil, err
	}

	crl, err = x509.ParseCRL(rawCRL)
	if err != nil {
		log.WithError(err).Debugf("CRL: Cannot parse CRL from '%s'", uri)
		return nil, err
	}

	err = issuerCert.CheckCRLSignature(crl)
	if err != nil {
		log.WithError(err).Warnf("CRL: Failed to check signature for CRL at %s", uri)
		return nil, err
	}

	v.ParsedCache.Put(uri, crl)

	return crl, nil
}

// Verify ensures configured CRLs do not contain certificate from passed chain
func (v DefaultCRLVerifier) Verify(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	for _, chain := range verifiedChains {
		log.Debugf("CRL: Verifying '%s'", chain[0].Subject.String())

		if len(v.Config.uri) == 0 && v.Config.fromCert == crlFromCertIgnore {
			log.Debugln("CRL: Skipping check since no config URI specified and we were told to ignore URIs from certificate")
			return nil
		}

		cert := chain[0]
		issuer := chain[1]

		for _, crlDistributionPoint := range cert.CRLDistributionPoints {
			log.Debugf("CRL: certificate contains CRL URI: %s", crlDistributionPoint)
		}

		queriedCRLs := make(map[string]struct{})

		if v.Config.uri != "" {
			crl, err := v.getCachedOrFetch(v.Config.uri, issuer)
			if err != nil {
				log.WithError(err).Debugf("CRL: Cannot get CRL from '%s'", v.Config.uri)
				return err
			}

			for _, revokedCertificate := range crl.TBSCertList.RevokedCertificates {
				if revokedCertificate.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					log.Warnf("CRL: Certificate %v was revoked at %v", cert.SerialNumber, revokedCertificate.RevocationTime)
					return fmt.Errorf("Certificate %v was revoked at %v", cert.SerialNumber, revokedCertificate.RevocationTime)
				}
			}

			queriedCRLs[v.Config.uri] = struct{}{}
			log.Debugln("CRL: OK, not found in list of revoked certificates")
		}

		if len(cert.CRLDistributionPoints) > 0 && v.Config.fromCert != crlFromCertIgnore {
			for _, crlDistributionPoint := range cert.CRLDistributionPoints {
				if _, ok := queriedCRLs[crlDistributionPoint]; ok {
					continue
				}

				log.Debugf("CRL: using '%s' from certificate", crlDistributionPoint)

				crl, err := v.getCachedOrFetch(crlDistributionPoint, issuer)
				if err != nil {
					log.WithError(err).Debugf("CRL: Cannot get CRL from '%s'", crlDistributionPoint)
					continue // temporary
					// return err
				}

				for _, revokedCertificate := range crl.TBSCertList.RevokedCertificates {
					if revokedCertificate.SerialNumber.Cmp(cert.SerialNumber) == 0 {
						log.Warnf("CRL: Certificate %v was revoked at %v", cert.SerialNumber, revokedCertificate.RevocationTime)
						return fmt.Errorf("Certificate %v was revoked at %v", cert.SerialNumber, revokedCertificate.RevocationTime)
					}
				}

				queriedCRLs[v.Config.uri] = struct{}{}
				log.Debugln("CRL: OK, not found in list of revoked certificates")
			}
		}
	}

	return nil
}
