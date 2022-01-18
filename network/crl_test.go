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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"testing"
	"time"
)

const (
	// Make sure you use either of these groups and don't mix their components

	// Default group, without intermediate certificates
	TestCertPrefix          = "../tests/ssl"
	TestCACertFilename      = "ca/ca.crt"
	TestCertFilename        = "acra-writer/acra-writer.crt"
	TestRevokedCertFilename = "acra-writer-revoked/acra-writer-revoked.crt"
	TestCRLFilename         = "ca/crl.pem"
	TestOCSPCertFilename    = "ocsp-responder/ocsp-responder.crt"
	TestOCSPKeyFilename     = "ocsp-responder/ocsp-responder.key"

	// A different group, uses intermediate CA
	TestCertPrefix3          = "../tests/ssl"
	TestCACertFilename3      = "ca/ca.crt"
	TestICACertFilename3     = "intermediate-ca/intermediate-ca.crt"
	TestCertFilename3        = "intermediate-acra-writer/intermediate-acra-writer.crt"
	TestRevokedCertFilename3 = "intermediate-acra-writer-revoked/intermediate-acra-writer-revoked.crt"
	TestCRLFilename3         = "intermediate-ca/crl.pem"
	TestOCSPCertFilename3    = "intermediate-ocsp-responder/intermediate-ocsp-responder.crt"
	TestOCSPKeyFilename3     = "intermediate-ocsp-responder/intermediate-ocsp-responder.key"

	// CRL that contains self-revoked root CA
	TestCRLFilenameRootSelfRevoked = "ca/crl_with_root.pem"
)

type TestCertGroup struct {
	prefix string

	ca             string
	intermediateCA string // may be empty (missing)

	validCert   string
	revokedCert string

	crl        string
	validCRL   string // if not empty, will be used instead of `crl` when checking valid chains
	revokedCRL string // if not empty, will be used instead of `crl` when checking revoked chains

	ocspCert string
	ocspKey  string

	validRawCerts       [][]byte
	validVerifiedChains [][]*x509.Certificate

	invalidRawCerts       [][]byte
	invalidVerifiedChains [][]*x509.Certificate
}

func getTestCertGroup(t *testing.T) TestCertGroup {
	validRawCerts, validVerifiedChains := getValidTestChain(t)
	invalidRawCerts, invalidVerifiedChains := getInvalidTestChain(t)

	return TestCertGroup{
		prefix:                TestCertPrefix,
		ca:                    TestCACertFilename,
		intermediateCA:        "",
		validCert:             TestCertFilename,
		revokedCert:           TestRevokedCertFilename,
		crl:                   TestCRLFilename,
		ocspCert:              TestOCSPCertFilename,
		ocspKey:               TestOCSPKeyFilename,
		validRawCerts:         validRawCerts,
		validVerifiedChains:   validVerifiedChains,
		invalidRawCerts:       invalidRawCerts,
		invalidVerifiedChains: invalidVerifiedChains,
	}
}

func getTestCertGroup3(t *testing.T) TestCertGroup {
	validRawCerts, validVerifiedChains := getValidTestChain3(t)
	invalidRawCerts, invalidVerifiedChains := getInvalidTestChain3(t)

	return TestCertGroup{
		prefix:                TestCertPrefix3,
		ca:                    TestCACertFilename3,
		intermediateCA:        TestICACertFilename3,
		validCert:             TestCertFilename3,
		revokedCert:           TestRevokedCertFilename3,
		crl:                   TestCRLFilename3,
		ocspCert:              TestOCSPCertFilename3,
		ocspKey:               TestOCSPKeyFilename3,
		validRawCerts:         validRawCerts,
		validVerifiedChains:   validVerifiedChains,
		invalidRawCerts:       invalidRawCerts,
		invalidVerifiedChains: invalidVerifiedChains,
	}
}

func getTestCertGroupOnlyRoot(t *testing.T) TestCertGroup {
	validRawCerts, validVerifiedChains := getTestChain(t, TestCertPrefix, TestCACertFilename)
	invalidRawCerts, invalidVerifiedChains := getTestChain(t, TestCertPrefix, TestCACertFilename)

	return TestCertGroup{
		prefix:                TestCertPrefix,
		ca:                    TestCACertFilename,
		intermediateCA:        "",
		validCert:             TestCACertFilename,
		revokedCert:           TestCACertFilename,
		validCRL:              TestCRLFilename,                // when using single cert as chain, ensure this is valid chain
		revokedCRL:            TestCRLFilenameRootSelfRevoked, // but also check that revocation works in this case
		ocspCert:              TestOCSPCertFilename,
		ocspKey:               TestOCSPKeyFilename,
		validRawCerts:         validRawCerts,
		validVerifiedChains:   validVerifiedChains,
		invalidRawCerts:       invalidRawCerts,
		invalidVerifiedChains: invalidVerifiedChains,
	}
}

func getTestCert(t *testing.T, filename string) ([]byte, *x509.Certificate) {
	rawCert, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("Cannot read certificate: %v\n", err)
	}

	cert, err := pemToX509Cert(rawCert)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v\n", err)
	}

	return rawCert, cert
}

func getTestCRL(t *testing.T, filename string) ([]byte, *CRLCacheItem) {
	rawCRL, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("Cannot read CRL: %v\n", err)
	}

	crl, err := x509.ParseCRL(rawCRL)
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v\n", err)
	}

	revokedCertificates := make(map[*big.Int]pkix.RevokedCertificate, len(crl.TBSCertList.RevokedCertificates))
	for _, cert := range crl.TBSCertList.RevokedCertificates {
		t.Logf("getTestCRL: revokedCertificates[%v] = %v\n", cert.SerialNumber, cert)
		revokedCertificates[cert.SerialNumber] = cert
	}

	cacheItem := &CRLCacheItem{Fetched: time.Now(), Extensions: crl.TBSCertList.Extensions, RevokedCertificates: revokedCertificates}

	return rawCRL, cacheItem
}

// Convert PEM-encoded certificate into DER and parse it into x509.Certificate
func pemToX509Cert(data []byte) (*x509.Certificate, error) {
	certDERBlock, _ := pem.Decode(data)
	if certDERBlock == nil {
		return nil, errors.New("Failed to decode PEM")
	}

	if certDERBlock.Type != "CERTIFICATE" {
		return nil, errors.New("Decoded DER block was not a certificate")
	}

	cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// Starts HTTP server on some random port, uses `mux` to handle requests,
// returns created server and IP:port of listening socket
func getTestHTTPServer(t *testing.T, mux *http.ServeMux) (*http.Server, string) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Cannot create TCP socket for HTTP server: %v", err)
	}

	addr := listener.Addr().String()

	httpServer := &http.Server{
		Handler: mux,
	}
	go func() {
		httpServer.Serve(listener)
	}()

	return httpServer, addr
}

func getTestChain(t *testing.T, prefix string, paths ...string) ([][]byte, [][]*x509.Certificate) {
	if len(paths) < 1 {
		t.Fatal("Certificate chain should contain at least one certificate\n")
	}

	rawCerts := [][]byte{}

	verifiedChains := [][]*x509.Certificate{}
	verifiedChains = append(verifiedChains, []*x509.Certificate{})

	// Read and parse certificates, construct the chain
	for _, p := range paths {
		filename := path.Join(prefix, p)

		rawCert, err := ioutil.ReadFile(filename)
		if err != nil {
			t.Fatalf("Cannot read certificate: %v\n", err)
		}

		cert, err := pemToX509Cert(rawCert)
		if err != nil {
			t.Fatalf("Cannot parse certificate: %v", err)
		}

		rawCerts = append(rawCerts, rawCert)
		verifiedChains[0] = append(verifiedChains[0], cert)
	}

	// Make sure this function was called with valid arguments
	for i, cert := range verifiedChains[0] {
		if i == 0 && cert.IsCA {
			// Avoid situations where we got two CA certificates,
			// first one should be used for authentication/encryption
			t.Logf("First certificate in chain (`%s`) should not be CA", cert.Subject.String())
		}

		var nextCert *x509.Certificate
		if i < len(verifiedChains[0])-1 {
			nextCert = verifiedChains[0][i+1]
		}

		if nextCert != nil {
			// Every certificate (except last) should be signed by the next one
			err := cert.CheckSignatureFrom(nextCert)
			if err != nil {
				t.Fatalf("Certificate `%s` was not signed by `%s`: %v\n", cert.Subject.String(), nextCert.Subject.String(), err)
			}
		}
	}

	return rawCerts, verifiedChains
}

func getValidTestChain(t *testing.T) ([][]byte, [][]*x509.Certificate) {
	return getTestChain(
		t,
		TestCertPrefix,
		TestCertFilename,
		TestCACertFilename)
}

func getValidTestChain3(t *testing.T) ([][]byte, [][]*x509.Certificate) {
	return getTestChain(
		t,
		TestCertPrefix3,
		TestCertFilename3,
		TestICACertFilename3,
		TestCACertFilename3)
}

func getInvalidTestChain(t *testing.T) ([][]byte, [][]*x509.Certificate) {
	return getTestChain(
		t,
		TestCertPrefix,
		TestRevokedCertFilename,
		TestCACertFilename)
}

func getInvalidTestChain3(t *testing.T) ([][]byte, [][]*x509.Certificate) {
	return getTestChain(
		t,
		TestCertPrefix3,
		TestRevokedCertFilename3,
		TestICACertFilename3,
		TestCACertFilename3)
}

func TestCRLConfig(t *testing.T) {
	expectOk := func(url, fromCert string, checkWholeChain bool, cacheSize, cacheTime uint) {
		config, err := NewCRLConfig(url, fromCert, checkWholeChain, cacheSize, cacheTime)
		if config == nil || err != nil {
			t.Logf("url=%v, fromCert=%v, checkWholeChain=%v, cacheSize=%v, cacheTime=%v\n",
				url, fromCert, checkWholeChain, cacheSize, cacheTime)
			t.Logf("config=%v, err=%v\n", config, err)
			t.Fatal("Got `nil` result or unexpected error")
		}
	}

	expectErr := func(url, fromCert string, checkWholeChain bool, cacheSize, cacheTime uint) {
		config, err := NewCRLConfig(url, fromCert, checkWholeChain, cacheSize, cacheTime)
		if config != nil || err == nil {
			t.Logf("url=%v, fromCert=%v, checkWholeChain=%v, cacheSize=%v, cacheTime=%v\n",
				url, fromCert, checkWholeChain, cacheSize, cacheTime)
			t.Logf("config=%v, err=%v\n", config, err)
			t.Fatal("Got unexpected result or `nil` error")
		}
	}

	// Empty URL
	expectOk("", CrlFromCertUseStr, false, 1, 5)
	// Valid URL
	expectOk("http://127.0.0.1/main_crl.pem", CrlFromCertUseStr, false, 1, 5)
	// Different valid values for `--tls_crl_from_cert`, with different valid cache size/time
	expectOk("", CrlFromCertIgnoreStr, false, 2, 5)
	expectOk("", CrlFromCertUseStr, false, 100, 0)
	expectOk("", CrlFromCertUseStr, true, 0, 1)
	expectOk("", CrlFromCertUseStr, false, 1, 300)
	expectOk("", CrlFromCertTrustStr, true, 1, 0)
	expectOk("", CrlFromCertPreferStr, false, 1, 0)

	// Invalid URL
	expectErr("htt://invalid url", CrlFromCertUseStr, false, 1, 5)
	// Invalid value of `--tls_crl_from_cert`
	expectErr("", "IgNoRe", false, 1, 5)
	// Invalid value of `--tls_crl_cache_size` (too big)
	expectErr("", CrlFromCertUseStr, false, CrlCacheSizeMax+1, 5)
	// Invalid value of `--tls_crl_cache_time` (too big)
	expectErr("", CrlFromCertUseStr, false, 1, CrlCacheTimeMax+1)
}

func TestDefaultCRLClientHTTP(t *testing.T) {
	rawCRL, _ := getTestCRL(t, path.Join(TestCertPrefix, TestCRLFilename))

	mux := http.NewServeMux()
	mux.HandleFunc("/test_crl.pem", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(200)
		res.Header().Add("Content-Type", "application/pem-certificate-chain")
		res.Write(rawCRL)
	})

	httpServer, addr := getTestHTTPServer(t, mux)
	defer httpServer.Close()

	crlClient := NewDefaultCRLClient()

	//
	// Test with valid URL
	//
	url := fmt.Sprintf("http://%s/test_crl.pem", addr)

	fetchedCRL, err := crlClient.Fetch(url, false)
	if err != nil {
		t.Fatalf("Unexpected error during reading %s: %v\n", url, err)
	}

	if !bytes.Equal(rawCRL, fetchedCRL) {
		t.Fatal("CRLClient returned mismatched data\n")
	}

	//
	// Test with invalid URL (i.e. when server returns 404 not found or any other error)
	//
	url = fmt.Sprintf("http://%s/wrong_filename.pem", addr)

	fetchedCRL, err = crlClient.Fetch(url, false)
	if err == nil {
		t.Fatal("Unexpected success during reading CRL from wrong URL\n")
	} else {
		t.Logf("(Expected) fetch error: %v\n", err)
	}

	if fetchedCRL != nil {
		t.Fatal("Fetched CRL is not nil\n")
	}
}

func TestDefaultCRLClientFile(t *testing.T) {
	rawCRL, _ := getTestCRL(t, path.Join(TestCertPrefix, TestCRLFilename))

	file, err := ioutil.TempFile("", "go_test_crl_*.pem")
	if err != nil {
		t.Fatalf("Cannot create temporary file to store CRL: %v\n", err)
	}
	defer os.Remove(file.Name())

	_, err = file.Write(rawCRL)
	if err != nil {
		t.Fatalf("Cannot write CRL to temporary file: %v\n", err)
	}

	crlClient := NewDefaultCRLClient()

	url := fmt.Sprintf("file://%s", file.Name())

	fetchedCRL, err := crlClient.Fetch(url, true)
	if err != nil {
		t.Fatalf("Unexpected error during reading %s: %v\n", url, err)
	}

	if !bytes.Equal(rawCRL, fetchedCRL) {
		t.Fatal("CRLClient returned mismatched data\n")
	}

	fetchedCRL, err = crlClient.Fetch(url, false)
	if fetchedCRL != nil || err != ErrFetchDeniedForLocalURL {
		t.Fatalf("Unexpected error when fetching file:// URL that should be denied: %v\n", err)
	}
}

func TestLRUCRLCache(t *testing.T) {
	// Same as TestDefaultCRLCache, but with *pkix.CertificateList instead of []byte as value
	cache := NewLRUCRLCache(4)

	_, cacheItem := getTestCRL(t, path.Join(TestCertPrefix, TestCRLFilename))

	// we don't expect to see any items in cache when it's created
	cachedCRL, err := cache.Get("test1")
	if cachedCRL != nil {
		t.Fatal("Unexpected data while reading empty cache\n")
	}
	if err == nil {
		t.Fatal("No expected error while reading empty cache\n")
	}

	// let's insert something
	cache.Put("test1", cacheItem)
	cachedCRL, err = cache.Get("test1")
	if cachedCRL == nil {
		t.Fatal("Unexpected fail while reading recently inserted cache item\n")
	}
	if err != nil {
		t.Fatal("Unexpected error while reading recently inserted cache item\n")
	}

	// and test removal
	err = cache.Remove("test1")
	if err != nil {
		t.Fatal("Unexpected error while removing recently inserted cache item\n")
	}
	cachedCRL, err = cache.Get("test1")
	if cachedCRL != nil {
		t.Fatal("Unexpected data while reading removed cache item\n")
	}
	if err == nil {
		t.Fatal("Unexpected error while reading removed cache item\n")
	}
}

func testDefaultCRLVerifierWithGroupValid(t *testing.T, certGroup TestCertGroup) {
	var rawCRL []byte
	if certGroup.validCRL != "" {
		rawCRL, _ = getTestCRL(t, path.Join(certGroup.prefix, certGroup.validCRL))
	} else {
		rawCRL, _ = getTestCRL(t, path.Join(certGroup.prefix, certGroup.crl))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/test_crl.pem", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(200)
		res.Header().Add("Content-Type", "application/pem-certificate-chain")
		res.Write(rawCRL)
	})

	httpServer, addr := getTestHTTPServer(t, mux)
	defer httpServer.Close()

	// Test with valid URL
	url := fmt.Sprintf("http://%s/test_crl.pem", addr)

	crlConfig := CRLConfig{fromCert: crlFromCertUse, cacheSize: 16, cacheTime: time.Second}
	crlVerifier := DefaultCRLVerifier{Config: crlConfig, Client: NewDefaultCRLClient(), Cache: NewLRUCRLCache(16)}

	// Test valid certificate chain

	certGroup.validVerifiedChains[0][0].CRLDistributionPoints = []string{url}

	err := crlVerifier.Verify(certGroup.validRawCerts, certGroup.validVerifiedChains)
	if err != nil {
		t.Fatalf("Unexpected error for valid certificate: %v\n", err)
	}
}

func testDefaultCRLVerifierWithGroupRevoked(t *testing.T, certGroup TestCertGroup) {
	var rawCRL []byte
	if certGroup.revokedCRL != "" {
		rawCRL, _ = getTestCRL(t, path.Join(certGroup.prefix, certGroup.revokedCRL))
	} else {
		rawCRL, _ = getTestCRL(t, path.Join(certGroup.prefix, certGroup.crl))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/test_crl.pem", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(200)
		res.Header().Add("Content-Type", "application/pem-certificate-chain")
		res.Write(rawCRL)
	})

	httpServer, addr := getTestHTTPServer(t, mux)
	defer httpServer.Close()

	// Test with valid URL
	url := fmt.Sprintf("http://%s/test_crl.pem", addr)

	crlConfig := CRLConfig{fromCert: crlFromCertUse, cacheSize: 16, cacheTime: time.Second}
	crlVerifier := DefaultCRLVerifier{Config: crlConfig, Client: NewDefaultCRLClient(), Cache: NewLRUCRLCache(16)}

	// Test invalid certificate chain that contains revoked certificate

	certGroup.invalidVerifiedChains[0][0].CRLDistributionPoints = []string{url}

	err := crlVerifier.Verify(certGroup.invalidRawCerts, certGroup.invalidVerifiedChains)
	if err == nil {
		t.Fatal("Unexpected success when verifying revoked certificate\n")
	}
	if err != ErrCertWasRevoked {
		t.Logf("Verify error: %v\n", err)
		t.Fatalf("Expected error: %d\n", ErrCertWasRevoked)
	}
	t.Logf("(Expected) verify error: %v\n", err)
}

func testDefaultCRLVerifierWithGroup(t *testing.T, certGroup TestCertGroup) {
	testDefaultCRLVerifierWithGroupValid(t, certGroup)
	testDefaultCRLVerifierWithGroupRevoked(t, certGroup)
}

func TestDefaultCRLVerifier(t *testing.T) {
	// testDefaultCRLVerifierWithGroup(t, getTestCertGroup(t))
	// testDefaultCRLVerifierWithGroup(t, getTestCertGroup3(t))
	// testDefaultCRLVerifierWithGroup(t, getTestCertGroupOnlyRoot(t))
}

func TestCheckCertWithCRL(t *testing.T) {
	// Test function checkCertWithCRL() used inside DefaultCRLVerifier.verifyCertWithIssuer(),
	// to be precise, test handling of different extensions in CRL

	// Extension processing is only done if revoked certificate S/N matches, so we gotta use revoked one,
	// thus, tested function should either return ErrCertWasRevoked or ErrUnknownCRLExtensionOID;
	// this behavior may be extended in future

	setCertificateExtensions := func(cacheItem *CRLCacheItem, extensions []pkix.Extension) {
		for _, revokedCert := range cacheItem.RevokedCertificates {
			revokedCert.Extensions = extensions
		}
	}

	expectOk := func(cert *x509.Certificate, cacheItem *CRLCacheItem) {
		t.Logf("expectOk %v\n", cacheItem)
		err := checkCertWithCRL(cert, cacheItem)
		if err != ErrCertWasRevoked {
			t.Logf("err=%v\n", err)
			t.Fatal("Got unexpected error")
		}
	}

	expectErr := func(cert *x509.Certificate, cacheItem *CRLCacheItem) {
		t.Logf("expectErr %v\n", cacheItem)
		err := checkCertWithCRL(cert, cacheItem)
		if err == ErrCertWasRevoked {
			t.Fatal("Got ErrCertWasRevoked, but expected error about extensions")
		} else {
			t.Logf("(Expected) err=%v\n", err)
		}
	}

	certGroup := getTestCertGroup(t)
	cert := certGroup.invalidVerifiedChains[0][0]
	_, cacheItem := getTestCRL(t, path.Join(certGroup.prefix, certGroup.crl))

	t.Logf("cert %v\n", cert)

	// Test with empty extensions lists in CRL
	cacheItem.Extensions = []pkix.Extension{}
	expectOk(cert, cacheItem)

	// Test with some known extension
	cacheItem.Extensions = []pkix.Extension{
		{Id: []int{2, 5, 29, 35}, Critical: true, Value: []byte{}},
	}
	expectOk(cert, cacheItem)

	// Test with some unknown critical extension
	cacheItem.Extensions = []pkix.Extension{
		{Id: []int{25, 100, 41}, Critical: true, Value: []byte{}},
	}
	expectErr(cert, cacheItem)

	// // Test with some unknown non-critical extension
	// cacheItem.extensions = []pkix.Extension{
	// 	{Id: []int{70, 1, 2, 3, 4}, Critical: false, Value: []byte{}},
	// }
	// expectOk(cert, cacheItem)

	// Test with empty extensions lists in revoked certificates
	setCertificateExtensions(cacheItem, []pkix.Extension{})
	expectOk(cert, cacheItem)

	// // Test with some known critical extension
	// setCertificateExtensions(cacheItem, []pkix.Extension{
	// 	{Id: []int{2, 5, 29, 15}, Critical: true, Value: []byte{}},
	// })
	// expectOk(cert, cacheItem)
	//
	// // Test with some known non-critical extension
	// setCertificateExtensions(cacheItem, []pkix.Extension{
	// 	{Id: []int{2, 5, 29, 35}, Critical: false, Value: []byte{}},
	// })
	// expectOk(cert, cacheItem)
	//
	// // Test with some unknown critical extension
	// setCertificateExtensions(cacheItem, []pkix.Extension{
	// 	{Id: []int{25, 100, 41}, Critical: true, Value: []byte{}},
	// })
	// expectErr(cert, cacheItem)
	//
	// // Test with some unknown non-critical extension
	// setCertificateExtensions(cacheItem, []pkix.Extension{
	// 	{Id: []int{70, 1, 2, 3, 4}, Critical: false, Value: []byte{}},
	// })
	// expectOk(cert, cacheItem)
}
