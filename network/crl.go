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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io/ioutil"
	"net/http"
	url_ "net/url"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/golang/groupcache/lru"
)

// Errors returned by CRL verifier
var (
	ErrInvalidConfigCRLFromCert     = errors.New("invalid `tls_crl_from_cert` value")
	ErrInvalidConfigCRLCacheSize    = errors.New("invalid `tls_crl_cache_size` value")
	ErrInvalidConfigCRLCacheTime    = errors.New("invalid `tls_crl_cache_time` value")
	ErrHTTPServerReturnedError      = errors.New("server returned non-OK status")
	ErrFetchDeniedForLocalURL       = errors.New("not allowed to fetch from local (file://) URLs")
	ErrFetchCRLUnsupportedURLScheme = errors.New("cannot fetch CRL, unsupported URL scheme")
	ErrCacheKeyNotFound             = errors.New("cannot find cached CRL with given URL")
	ErrOutdatedCRL                  = errors.New("fetched CRLs NextUpdate is behind current time")
	ErrUnknownCRLExtensionOID       = errors.New("unable to process unknown critical extension inside CRL")
	ErrUnimplementedCRLExtension    = errors.New("handling of CRL extension is not yet implemented")
)

// --tls_crl_from_cert=<use|trust|prefer|ignore>
const (
	// If certificate contains CRL distribution point(s), use them, _after_ trying configured URL
	CrlFromCertUseStr = "use"
	// If certificate contains CRL distribution point(s), use them, and don't use configured URL in this case
	CrlFromCertTrustStr = "trust"
	// If certificate contains CRL distribution point(s), use them, _before_ trying configured URL
	CrlFromCertPreferStr = "prefer"
	// Ignore CRL distribution points listed in certificate
	CrlFromCertIgnoreStr = "ignore"
)

// CrlFromCertValuesList contains all possible values for flag `--tls_crl_from_cert`
var CrlFromCertValuesList = []string{
	CrlFromCertUseStr,
	CrlFromCertTrustStr,
	CrlFromCertPreferStr,
	CrlFromCertIgnoreStr,
}

var (
	crlFromCertValValues = map[string]int{
		CrlFromCertUseStr:    crlFromCertUse,
		CrlFromCertTrustStr:  crlFromCertTrust,
		CrlFromCertPreferStr: crlFromCertPrefer,
		CrlFromCertIgnoreStr: crlFromCertIgnore,
	}
)

const (
	crlFromCertUse int = iota
	crlFromCertTrust
	crlFromCertPrefer
	crlFromCertIgnore
)

const (
	// CrlDefaultCacheSize is default value for `--tls_crl_cache_size`
	CrlDefaultCacheSize = 16
	// CrlCacheSizeMax is max value for `--tls_crl_cache_size`
	CrlCacheSizeMax = 1_000_000
	// CrlDisableCacheSize will disable caching if set in `--tls_crl_cache_size`
	CrlDisableCacheSize = 0
	// CrlCacheTimeMax is max value for `--tls_crl_cache_time`
	CrlCacheTimeMax = 300
	// CrlDisableCacheTime will disable caching if set in `--tls_crl_cache_time`
	CrlDisableCacheTime = 0
)

// CRLConfig contains configuration related to certificate validation using CRL
type CRLConfig struct {
	url                      string
	fromCert                 int // crlFromCert*
	checkOnlyLeafCertificate bool
	cacheSize                uint
	cacheTime                time.Duration
	ClientAuthType           tls.ClientAuthType
}

const (
	// CrlHTTPClientDefaultTimeout is default timeout for HTTP client used to fetch CRLs
	CrlHTTPClientDefaultTimeout = time.Second * time.Duration(20)
)

// NewCRLConfig creates new CRLConfig
func NewCRLConfig(url, fromCert string, checkOnlyLeafCertificate bool, cacheSize, cacheTime uint) (*CRLConfig, error) {
	fromCertVal, ok := crlFromCertValValues[fromCert]
	if !ok {
		return nil, ErrInvalidConfigCRLFromCert
	}

	if cacheSize > CrlCacheSizeMax {
		return nil, ErrInvalidConfigCRLCacheSize
	}

	if cacheTime > CrlCacheTimeMax {
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
		_, err = crlClient.Fetch(url, true)
		if err != nil {
			log.WithError(err).WithField("url", url).Warnln("CRL: Cannot fetch configured URL")
		}
	}

	return &CRLConfig{
		url:                      url,
		fromCert:                 fromCertVal,
		checkOnlyLeafCertificate: checkOnlyLeafCertificate,
		cacheSize:                cacheSize,
		cacheTime:                time.Second * time.Duration(cacheTime),
		ClientAuthType:           tls.RequireAndVerifyClientCert,
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
	return c.cacheTime != CrlDisableCacheTime && c.cacheSize != CrlDisableCacheSize
}

// CRLClient is used to fetch CRL from some URL
type CRLClient interface {
	// Fetch fetches CRL from passed URL (can be either http:// or file://),
	// allowLocal controls whether file:// will be handled (should not be allowed for URLs from certificates)
	Fetch(url string, allowLocal bool) ([]byte, error)
}

// DefaultCRLClient is a default implementation of CRLClient
// (as opposed to stub ones used in tests)
type DefaultCRLClient struct {
	httpClient *http.Client
}

// NewDefaultCRLClient creates new DefaultCRLClient
func NewDefaultCRLClient() DefaultCRLClient {
	return DefaultCRLClient{httpClient: &http.Client{
		Timeout: CrlHTTPClientDefaultTimeout,
	}}
}

// Fetch fetches CRL from passed URL (can be either http:// or file://),
// allowLocal controls whether file:// will be handled (should not be allowed for URLs from certificates)
func (c DefaultCRLClient) Fetch(url string, allowLocal bool) ([]byte, error) {
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
		if !allowLocal {
			return nil, ErrFetchDeniedForLocalURL
		}

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
	Fetched             time.Time                           // When this CRL was fetched and cached
	CRL                 pkix.CertificateList                // Parsed CRL itself
	RevokedCertificates map[string]*pkix.RevokedCertificate // Copy of CRL.TBSCertList.RevokedCertificates with SerialNumber as key
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
func (v DefaultCRLVerifier) getCachedOrFetch(url string, allowLocal bool, issuerCert *x509.Certificate) (*CRLCacheItem, error) {
	// Try v.Cache first, but only if caching is enabled (cache time > 0)
	if v.Config.isCachingEnabled() {
		cacheItem, err := v.Cache.Get(v.Config.url)
		if cacheItem != nil {
			if err != nil {
				// non-empty result + error, should never happen
				return nil, err
			}

			if time.Now().Before(cacheItem.Fetched.Add(v.Config.cacheTime)) && time.Now().Before(cacheItem.CRL.TBSCertList.NextUpdate) {
				return cacheItem, nil
			}
		}
	}

	// Not found in cache (or the CRL was outdated), gotta fetch
	rawCRL, err := v.Client.Fetch(url, allowLocal)
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

	// Cannot use big.Int as map key unfortunately, using string with hex-encoded serial instead
	revokedCertificates := make(map[string]*pkix.RevokedCertificate, len(crl.TBSCertList.RevokedCertificates))
	for _, cert := range crl.TBSCertList.RevokedCertificates {
		revokedCertificates[cert.SerialNumber.Text(16)] = &cert
	}

	// We don't need this array anymore as all revoked certificates are now inside the `revokedCertificates` map
	crl.TBSCertList.RevokedCertificates = nil

	cacheItem := &CRLCacheItem{
		Fetched:             time.Now(),
		CRL:                 *crl,
		RevokedCertificates: revokedCertificates,
	}

	if v.Config.isCachingEnabled() {
		v.Cache.Put(url, cacheItem)
	}

	return cacheItem, nil
}

// Returns `nil` if certificate was not cound in CRL, returns error if it was there
// or if there was unknown Object ID in revoked certificate extensions
func checkCertWithCRL(cert *x509.Certificate, cacheItem *CRLCacheItem) error {
	for _, extension := range cacheItem.CRL.TBSCertList.Extensions {
		// For CRL v2 (RFC 5280 section 5.2), CRL issuers are REQUIRED to include
		// the authority key identifier (Section 5.2.1) and the CRL number (Section 5.2.3).
		// TODO handle all these extensions; this will require some refactoring:
		//      create DB with revoked certificates, update it from delta CRL or rewrite from usual CRL;
		//      these extensions cannot exist in older CRL v1 though
		//      (like the one generated with `openssl ca -gencrl ...` without `-crlexts` option)
		switch extension.Id.String() {
		case "2.5.29.35":
			// section 5.2.1 (4.2.1.1), id-ce-authorityKeyIdentifier

		case "2.5.29.18":
			// section 5.2.2 (4.2.1.7), id-ce-issuerAltName

		case "2.5.29.20":
			// section 5.2.3, id-ce-cRLNumber

		case "2.5.29.27":
			// section 5.2.4, id-ce-deltaCRLIndicator
			// > The delta CRL indicator is a critical CRL extension that identifies a CRL as being a delta CRL
			log.WithField("oid", extension.Id.String()).Warnln("CRL: handling of CRL extension is not yet implemented")
			return ErrUnimplementedCRLExtension

		default:
			if extension.Critical {
				log.WithField("oid", extension.Id.String()).Warnln("CRL: Unable to process critical extension with unknown Object ID")
				return ErrUnknownCRLExtensionOID
			}
			log.WithField("oid", extension.Id.String()).Debugln("CRL: Unable to process non-critical extension with unknown Object ID")
		}
	}

	revokedCertificate, ok := cacheItem.RevokedCertificates[cert.SerialNumber.Text(16)]
	if !ok {
		return nil
	}

	log.WithField("extensions", revokedCertificate.Extensions).Debugln("Revoked certificate extensions")
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

		// if crlToCheck.fromCert == false, then URL comes from config, then allowLocal = true
		// if crlToCheck.fromCert == true, CRLClient should reject file:// URLs
		crl, err := v.getCachedOrFetch(crlToCheck.url, !crlToCheck.fromCert, issuer)
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
		if len(chain) == 0 {
			switch v.Config.ClientAuthType {
			case tls.NoClientCert, tls.RequestClientCert, tls.RequireAnyClientCert:
				log.Infoln("CRL: Empty verified certificates chain, nothing to do")
				return nil
			default: // tls.VerifyClientCertIfGiven, tls.RequireAndVerifyClientCert
				return ErrEmptyCertChain
			}
		}

		if len(chain) == 1 {
			log.WithField("serial", chain[0].SerialNumber).
				Warnln("CRL: Certificate chain consists of one root certificate, it is recommended to use dedicated non-root certificates for TLS handshake")
			return v.verifyCertWithIssuer(chain[0], chain[0], false)
		}

		for i := 0; i < len(chain)-1; i++ {
			cert := chain[i]
			issuer := chain[i+1]

			// 3rd argument, useConfigURL, whether to use CRL URL from configuration (if set),
			// don't use it for other certificates except end one (i.e. don't use it when checking intermediate
			// certificates because v.Config.checkOnlyLeafCertificate == false)
			err := v.verifyCertWithIssuer(cert, issuer, i == 0)
			if err != nil {
				return err
			}

			if v.Config.checkOnlyLeafCertificate {
				break
			}
		}
	}

	return nil
}
