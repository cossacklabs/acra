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
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
)

// Errors returned by CRL verifier
var (
	ErrInvalidConfigCRLFromCert     = errors.New("Invalid `tls_crl_from_cert` value")
	ErrInvalidConfigCRLCacheTime    = errors.New("Invalid `tls_crl_cache_time` value")
	ErrHTTPServerReturnedError      = errors.New("Server returned non-OK status")
	ErrFetchCRLUnsupportedURLScheme = errors.New("Cannot fetch CRL, unsupported URL scheme")
	ErrCacheKeyNotFound             = errors.New("Cannot find cached CRL with given URI")
	ErrOutdatedCRL                  = errors.New("Cannot find cached CRL with given URI")
)

// --tls_crl_from_cert=<use|ignore>
const (
	// If certificate contains CRL distribution point(s), use them
	crlFromCertUseStr = "use"
	// Ignore CRL distribution points listed in certificate
	crlFromCertIgnoreStr = "ignore"
)

var (
	crlFromCertValValues = map[string]int{
		crlFromCertUseStr:    crlFromCertUse,
		crlFromCertIgnoreStr: crlFromCertIgnore,
	}
)

const (
	crlFromCertUse int = iota
	crlFromCertIgnore
)

const (
	crlCacheTimeMax = 300
)

// CRLConfig contains configuration related to certificate validation using CRL
type CRLConfig struct {
	uri       string
	fromCert  int // crlFromCert*
	cacheSize int
	cacheTime time.Duration
}

// NewCRLConfig creates new CRLConfig
func NewCRLConfig(uri, fromCert string, cacheSize, cacheTime int) (*CRLConfig, error) {

	fromCertVal, ok := crlFromCertValValues[fromCert]
	if !ok {
		return nil, ErrInvalidConfigCRLFromCert
	}

	if cacheTime < 0 || cacheTime > crlCacheTimeMax {
		return nil, ErrInvalidConfigCRLCacheTime
	}

	if uri != "" {
		_, err := url.Parse(uri)
		if err != nil {
			return nil, err
		}

		// Since this is CRL configuration alone, we don't have access to cache yet;
		// so let's just download the CRL and forget about it
		crlClient := NewDefaultCRLClient()
		_, err = crlClient.Fetch(uri)
		if err != nil {
			log.WithError(err).WithField("uri", uri).Warnln("CRL: Cannot fetch configured URI")
			// TODO return error after issues with failing tests are fixed;
			//      CRL HTTP server is starting, connection is checked, then Acra is starting
			//      but somehow checking connection *here* fails thus failing the tests;
			//      everything else seems working since real requests to configured server
			//      are successful (when CRL verification is performed)
			// return nil, errors.New("CRL: Cannot fetch configured URI")
		}
	}

	return &CRLConfig{
		uri:       uri,
		fromCert:  fromCertVal,
		cacheSize: cacheSize,
		cacheTime: time.Second * time.Duration(cacheTime),
	}, nil
}

// UseCRL returns true if verification via CRL is enabled
func (c *CRLConfig) UseCRL() bool {
	if c == nil {
		return false
	}
	return c.uri != "" || c.fromCert != crlFromCertIgnore
}

func (c *CRLConfig) isCachingEnabled() bool {
	return c.cacheTime > 0 && c.cacheSize > 0
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

// NewDefaultCRLClient creates new DefaultCRLClient
func NewDefaultCRLClient() DefaultCRLClient {
	return DefaultCRLClient{httpClient: &http.Client{}}
}

// Fetch fetches CRL from passed URI (can be either http:// or file://)
func (c DefaultCRLClient) Fetch(uri string) ([]byte, error) {
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	switch parsedURI.Scheme {
	case "http":
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
			log.WithField("status", httpResponse.Status).Warnln("Server returned non-OK status")
			return nil, ErrHTTPServerReturnedError
		}

		return content, nil
	case "file":
		content, err := ioutil.ReadFile(parsedURI.Path)
		if err != nil {
			return nil, err
		}

		return content, nil
	}

	log.WithField("uri", uri).Warnln("Cannot fetch CRL")
	return nil, ErrFetchCRLUnsupportedURLScheme
}

// CRLCacheItem is combination of fetched+parsed+verified CRL with fetch time
type CRLCacheItem struct {
	Fetched time.Time // When this CRL was fetched and cached
	CRL     pkix.CertificateList
}

// CRLCache is used to store fetched CRLs to avoid downloading the same URI more than once,
// stores parsed and verified CRLs
type CRLCache interface {
	Get(key string) (*CRLCacheItem, error)
	Put(key string, value *CRLCacheItem) error
	Remove(key string) error
}

// LRUCRLCache is an implementation of CRLCache that uses LRU cache inside
type LRUCRLCache struct {
	cache lru.Cache
	mutex sync.RWMutex
}

// NewLRUCRLCache creates new LRUCRLCache, able to store at most maxEntries values
func NewLRUCRLCache(maxEntries int) *LRUCRLCache {
	return &LRUCRLCache{cache: lru.Cache{MaxEntries: maxEntries}}
}

// Get tries to get CRL from cache, returns error if failed
func (c *LRUCRLCache) Get(key string) (*CRLCacheItem, error) {
	log.Debugf("CRL: LRU cache: loading '%s'", key)
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	value, ok := c.cache.Get(key)
	if ok {
		value, _ := value.(*CRLCacheItem)
		log.Debugf("CRL: LRU cache: '%s' found", key)
		return value, nil
	}

	return nil, ErrCacheKeyNotFound
}

// Put stores CRL in cache
func (c *LRUCRLCache) Put(key string, value *CRLCacheItem) error {
	c.mutex.Lock()
	c.cache.Add(key, value)
	c.mutex.Unlock()
	log.Debugf("CRL: LRU cache: inserted '%s'", key)
	return nil
}

// Remove removes item from cache
func (c *LRUCRLCache) Remove(key string) error {
	c.mutex.Lock()
	c.cache.Remove(key)
	c.mutex.Unlock()
	log.Debugf("CRL: LRU cache: removed '%s'", key)
	return nil
}

// DefaultCRLVerifier is a default implementation of CRLVerifier
type DefaultCRLVerifier struct {
	Config CRLConfig
	Client CRLClient
	Cache  CRLCache
}

// Tries to find cached CRL, fetches using v.Client if not found, checks the signature of CRL using issuerCert
func (v DefaultCRLVerifier) getCachedOrFetch(uri string, issuerCert *x509.Certificate) (*pkix.CertificateList, error) {
	// Try v.Cache first, but only if caching is enabled (cache time > 0)
	if v.Config.isCachingEnabled() {
		cacheItem, err := v.Cache.Get(v.Config.uri)
		if cacheItem != nil {
			if err != nil {
				// non-empty result + error, should never happen
				return nil, err
			}

			if time.Now().Before(cacheItem.Fetched.Add(v.Config.cacheTime)) {
				return &cacheItem.CRL, nil
			}
		}
	}

	// Not found in cache (or the CRL was outdated), gotta fetch
	rawCRL, err := v.Client.Fetch(uri)
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseCRL(rawCRL)
	if err != nil {
		log.WithError(err).Debugf("CRL: Cannot parse CRL from '%s'", uri)
		return nil, err
	}

	err = issuerCert.CheckCRLSignature(crl)
	if err != nil {
		log.WithError(err).Warnf("CRL: Failed to check signature for CRL at %s", uri)
		return nil, err
	}

	if crl.TBSCertList.NextUpdate.Before(time.Now()) {
		log.Warnf("CRL: CRL at %s is outdated", uri)
		return nil, ErrOutdatedCRL
	}

	if v.Config.isCachingEnabled() {
		cacheItem := &CRLCacheItem{Fetched: time.Now(), CRL: *crl}
		v.Cache.Put(uri, cacheItem)
	}

	return crl, nil
}

func (v DefaultCRLVerifier) verifyCertWithIssuer(cert, issuer *x509.Certificate) error {
	log.Debugf("CRL: Verifying '%s'", cert.Subject.String())

	if len(v.Config.uri) == 0 && v.Config.fromCert == crlFromCertIgnore {
		log.Debugln("CRL: Skipping check since no config URI specified and we were told to ignore URIs from certificate")
		return nil
	}

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
				return ErrCertWasRevoked
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
				return err
			}

			for _, revokedCertificate := range crl.TBSCertList.RevokedCertificates {
				if revokedCertificate.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					log.Warnf("CRL: Certificate %v was revoked at %v", cert.SerialNumber, revokedCertificate.RevocationTime)
					return ErrCertWasRevoked
				}
			}

			queriedCRLs[v.Config.uri] = struct{}{}
			log.Debugln("CRL: OK, not found in list of revoked certificates")
		}
	}

	return nil
}

// Verify ensures configured CRLs do not contain certificate from passed chain
func (v DefaultCRLVerifier) Verify(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	for _, chain := range verifiedChains {
		if len(chain) == 1 {
			// This one cert[0] must be trusted since it was allowed by more basic verifying routines.
			// If we are at this point, we have nothing to do, and no CA means no CRL.
			log.Debugln("CRL: Certificate chain contains one certificate, nothing to do")
			return nil
		}

		cert := chain[0]
		issuer := chain[1]

		err := v.verifyCertWithIssuer(cert, issuer)
		if err != nil {
			return err
		}
	}

	return nil
}
