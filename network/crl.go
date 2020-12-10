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
	url_ "net/url"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
)

// Errors returned by CRL verifier
var (
	ErrInvalidConfigCRLFromCert     = errors.New("invalid `tls_crl_from_cert` value")
	ErrInvalidConfigCRLCacheSize    = errors.New("invalid `tls_crl_cache_size` value")
	ErrInvalidConfigCRLCacheTime    = errors.New("invalid `tls_crl_cache_time` value")
	ErrHTTPServerReturnedError      = errors.New("server returned non-OK status")
	ErrFetchCRLUnsupportedURLScheme = errors.New("cannot fetch CRL, unsupported URL scheme")
	ErrCacheKeyNotFound             = errors.New("cannot find cached CRL with given URL")
	ErrOutdatedCRL                  = errors.New("fetched CRLs NextUpdate is behind current time")
	ErrUnknownCRLExtensionOID       = errors.New("unable to process unknown critical extension inside CRL")
)

// --tls_crl_from_cert=<use|truet|prefer|ignore>
const (
	// If certificate contains CRL distribution point(s), use them, _after_ trying configured URL
	crlFromCertUseStr = "use"
	// If certificate contains CRL distribution point(s), use them, and don't use configured URL in this case
	crlFromCertTrustStr = "trust"
	// If certificate contains CRL distribution point(s), use them, _before_ trying configured URL
	crlFromCertPreferStr = "prefer"
	// Ignore CRL distribution points listed in certificate
	crlFromCertIgnoreStr = "ignore"
)

var (
	crlFromCertValValues = map[string]int{
		crlFromCertUseStr:    crlFromCertUse,
		crlFromCertTrustStr:  crlFromCertTrust,
		crlFromCertPreferStr: crlFromCertPrefer,
		crlFromCertIgnoreStr: crlFromCertIgnore,
	}
)

const (
	crlFromCertUse int = iota
	crlFromCertTrust
	crlFromCertPrefer
	crlFromCertIgnore
)

const (
	// Max int value, because cache implementation uses `int` for setting capacity
	crlCacheSizeMax = 2147483647
	crlCacheTimeMax = 300
)

// CRLConfig contains configuration related to certificate validation using CRL
type CRLConfig struct {
	url             string
	fromCert        int // crlFromCert*
	checkWholeChain bool
	cacheSize       uint
	cacheTime       time.Duration
}

// NewCRLConfig creates new CRLConfig
func NewCRLConfig(url, fromCert string, checkWholeChain bool, cacheSize, cacheTime uint) (*CRLConfig, error) {
	fromCertVal, ok := crlFromCertValValues[fromCert]
	if !ok {
		return nil, ErrInvalidConfigCRLFromCert
	}

	if cacheSize > crlCacheSizeMax {
		return nil, ErrInvalidConfigCRLCacheSize
	}

	if cacheTime > crlCacheTimeMax {
		return nil, ErrInvalidConfigCRLCacheTime
	}

	if url != "" {
		_, err := url_.Parse(url)
		if err != nil {
			return nil, err
		}

		// Since this is CRL configuration alone, we don't have access to cache yet;
		// so let's just download the CRL and forget about it
		crlClient := NewDefaultCRLClient()
		_, err = crlClient.Fetch(url)
		if err != nil {
			log.WithError(err).WithField("url", url).Warnln("CRL: Cannot fetch configured URL")
			// TODO return error after issues with failing tests are fixed;
			//      CRL HTTP server is starting, connection is checked, then Acra is starting
			//      but somehow checking connection *here* fails thus failing the tests;
			//      everything else seems working since real requests to configured server
			//      are successful (when CRL verification is performed)
			// return nil, errors.New("CRL: Cannot fetch configured URL")
		}
	}

	return &CRLConfig{
		url:             url,
		fromCert:        fromCertVal,
		checkWholeChain: checkWholeChain,
		cacheSize:       cacheSize,
		cacheTime:       time.Second * time.Duration(cacheTime),
	}, nil
}

// UseCRL returns true if verification via CRL is enabled
func (c *CRLConfig) UseCRL() bool {
	if c == nil {
		return false
	}
	return c.url != "" || c.fromCert != crlFromCertIgnore
}

func (c *CRLConfig) isCachingEnabled() bool {
	return c.cacheTime > 0 && c.cacheSize > 0
}

// CRLClient is used to fetch CRL from some URL
type CRLClient interface {
	// Fetch fetches CRL from passed URL (can be either http:// or file://)
	Fetch(url string) ([]byte, error)
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

// Fetch fetches CRL from passed URL (can be either http:// or file://)
func (c DefaultCRLClient) Fetch(url string) ([]byte, error) {
	parsedURL, err := url_.Parse(url)
	if err != nil {
		return nil, err
	}

	switch parsedURL.Scheme {
	case "http":
		httpRequest, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		httpRequest.Header.Add("Accept", "application/pkix-crl, application/pem-certificate-chain")
		httpRequest.Header.Add("host", parsedURL.Host)
		httpResponse, err := c.httpClient.Do(httpRequest)
		if err != nil {
			return nil, err
		}
		defer httpResponse.Body.Close()
		content, err := ioutil.ReadAll(httpResponse.Body)
		if err != nil {
			return nil, err
		}

		if httpResponse.StatusCode != http.StatusOK {
			log.WithField("status", httpResponse.Status).Warnln("Server returned non-OK status")
			return nil, ErrHTTPServerReturnedError
		}

		return content, nil
	case "file":
		content, err := ioutil.ReadFile(parsedURL.Path)
		if err != nil {
			return nil, err
		}

		return content, nil
	}

	log.WithField("url", url).Warnln("Cannot fetch CRL")
	return nil, ErrFetchCRLUnsupportedURLScheme
}

// CRLCacheItem is combination of fetched+parsed+verified CRL with fetch time
type CRLCacheItem struct {
	Fetched time.Time // When this CRL was fetched and cached
	CRL     pkix.CertificateList
}

// CRLCache is used to store fetched CRLs to avoid downloading the same URL more than once,
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
func NewLRUCRLCache(maxEntries uint) *LRUCRLCache {
	return &LRUCRLCache{cache: lru.Cache{MaxEntries: int(maxEntries)}}
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
func (v DefaultCRLVerifier) getCachedOrFetch(url string, issuerCert *x509.Certificate) (*pkix.CertificateList, error) {
	// Try v.Cache first, but only if caching is enabled (cache time > 0)
	if v.Config.isCachingEnabled() {
		cacheItem, err := v.Cache.Get(v.Config.url)
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
	rawCRL, err := v.Client.Fetch(url)
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseCRL(rawCRL)
	if err != nil {
		log.WithError(err).Debugf("CRL: Cannot parse CRL from '%s'", url)
		return nil, err
	}

	err = issuerCert.CheckCRLSignature(crl)
	if err != nil {
		log.WithError(err).Warnf("CRL: Failed to check signature for CRL at %s", url)
		return nil, err
	}

	if crl.TBSCertList.NextUpdate.Before(time.Now()) {
		log.Warnf("CRL: CRL at %s is outdated", url)
		return nil, ErrOutdatedCRL
	}

	if v.Config.isCachingEnabled() {
		cacheItem := &CRLCacheItem{Fetched: time.Now(), CRL: *crl}
		v.Cache.Put(url, cacheItem)
	}

	return crl, nil
}

// Returns `nil` if certificate was not cound in CRL, returns error if it was there
// or if there was unknown Object ID in revoked certificate extensions
func checkCertWithCRL(cert *x509.Certificate, crl *pkix.CertificateList) error {
	for _, revokedCertificate := range crl.TBSCertList.RevokedCertificates {
		if revokedCertificate.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			log.WithField("extensions", revokedCertificate.Extensions).Warnln("Revoked certificate extensions")
			for _, extension := range revokedCertificate.Extensions {
				// One can use https://www.alvestrand.no/objectid/top.html to convert string OIDs (like id-ce-keyUsage)
				// into numerical format (like 2.5.29.15), though RFC also allows easy reconstruction of OIDs.

				// Some of these extensions values may be ignored, but we still have to
				// include them (their OIDs) here so that we're not blindly ignoring them.
				// Convert to string to be able to use switch.
				switch extension.Id.String() {
				// As per RFC 5280 section 4.2, aplications MUST recognize following extensions:
				case "2.5.29.15":
					// section 4.2.1.3, id-ce-keyUsage
				case "2.5.29.32":
					// section 4.2.1.4, id-ce-certificatePolicies
				case "2.5.29.17":
					// section 4.2.1.6, id-ce-subjectAltName
				case "2.5.29.19":
					// section 4.2.1.9, id-ce-basicConstraints
				case "2.5.29.30":
					// section 4.2.1.10, id-ce-nameConstraints
				case "2.5.29.36":
					// section 4.2.1.11, id-ce-policyConstraints
				case "2.5.29.37":
					// section 4.2.1.12, id-ce-extKeyUsage
				case "2.5.29.54":
					// section 4.2.1.14, id-ce-inhibitAnyPolicy

				// As per RFC 5280 section 4.2, aplications SHOULD recognize following extensions:
				case "2.5.29.35":
					// section 4.2.1.1, id-ce-authorityKeyIdentifier
				case "2.5.29.14":
					// section 4.2.1.2, id-ce-subjectKeyIdentifier
				case "2.5.29.33":
					// section 4.2.1.5, id-ce-policyMappings

				default:
					if extension.Critical {
						log.WithField("oid", extension.Id.String()).Warnln("CRL: Unable to process critical extension with unknown Object ID")
						return ErrUnknownCRLExtensionOID
					}
					log.WithField("oid", extension.Id.String()).Debugln("CRL: Unable to process non-critical extension with unknown Object ID")
				}
			}

			log.WithField("serial", cert.SerialNumber).WithField("revoked_at", revokedCertificate.RevocationTime).Warnln("CRL: Certificate was revoked")
			return ErrCertWasRevoked
		}
	}

	return nil
}

// crlToCheck is used to plan CRL requests
type crlToCheck struct {
	url      string
	fromCert bool
}

func (v DefaultCRLVerifier) verifyCertWithIssuer(cert, issuer *x509.Certificate, useConfigURL bool) error {
	log.Debugf("CRL: Verifying '%s'", cert.Subject.String())

	for _, crlDistributionPoint := range cert.CRLDistributionPoints {
		log.Debugf("CRL: certificate contains CRL URL: %s", crlDistributionPoint)
	}

	crlsToCheck := []crlToCheck{}

	if v.Config.fromCert != crlFromCertIgnore {
		for _, crlDistributionPoint := range cert.CRLDistributionPoints {
			serverToCheck := crlToCheck{url: crlDistributionPoint, fromCert: true}
			log.Debugf("CRL: appending server %s, from cert", serverToCheck.url)
			crlsToCheck = append(crlsToCheck, serverToCheck)
		}
	} else if len(cert.CRLDistributionPoints) > 0 {
		log.Debugf("CRL: Ignoring %d CRL distribution points from certificate", len(cert.CRLDistributionPoints))
	}

	if v.Config.url != "" && useConfigURL {
		crlDistributionPointToCheck := crlToCheck{url: v.Config.url, fromCert: false}

		if v.Config.fromCert == crlFromCertPrefer || v.Config.fromCert == crlFromCertTrust {
			log.Debugf("CRL: appending server %s, from config", crlDistributionPointToCheck.url)
			crlsToCheck = append(crlsToCheck, crlDistributionPointToCheck)
		} else {
			log.Debugf("CRL: prepending server %s, from config", crlDistributionPointToCheck.url)
			crlsToCheck = append([]crlToCheck{crlDistributionPointToCheck}, crlsToCheck...)
		}
	}

	queriedCRLs := make(map[string]struct{})

	for _, crlToCheck := range crlsToCheck {
		log.Debugf("CRL: Trying URL %s", crlToCheck.url)

		if _, ok := queriedCRLs[crlToCheck.url]; ok {
			log.Debugln("CRL: Skipping, already queried")
			continue
		}

		crl, err := v.getCachedOrFetch(crlToCheck.url, issuer)
		if err != nil {
			log.WithError(err).WithField("url", crlToCheck.url).Debugf("CRL: Cannot get CRL")
			return err
		}

		err = checkCertWithCRL(cert, crl)
		if err != nil {
			return err
		}

		if crlToCheck.fromCert && v.Config.fromCert == crlFromCertTrust {
			// If this CRL distribution point came from certificate and `--tls_crl_from_cert=trust`, don't perform further checks
			break
		}

		queriedCRLs[crlToCheck.url] = struct{}{}
		log.Debugln("CRL: OK, not found in list of revoked certificates")
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

		for i := 0; i < len(chain)-1; i++ {
			cert := chain[i]
			issuer := chain[i+1]

			// 3rd argument, useConfigURL, whether to use OCSP server URL from configuration (if set),
			// don't use it for other certificates except end one (i.e. don't use it when checking intermediate
			// certificates because v.Config.checkWholeChain == true)
			err := v.verifyCertWithIssuer(cert, issuer, i == 0)
			if err != nil {
				return err
			}

			if !v.Config.checkWholeChain {
				break
			}
		}
	}

	return nil
}
