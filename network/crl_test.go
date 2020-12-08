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
	"net"
	"net/http"
	"os"
	"path"
	"testing"
	"time"
)

const (
	// Default group, without intermediate certificates
	TestCertPrefix          = "../tests/ssl"
	TestCACertFilename      = "ca/ca.crt"
	TestCertFilename        = "acra-writer/acra-writer.crt"
	TestRevokedCertFilename = "acra-writer-revoked/acra-writer-revoked.crt"
	TestCRLFilename         = "crl.pem"
	TestOCSPCertFilename    = "ocsp-responder/ocsp-responder.crt"
	TestOCSPKeyFilename     = "ocsp-responder/ocsp-responder.key"

	// TODO add certificates for this group, fix paths, uncomment related code
	// A different group, uses intermediate CA
	// TestCertPrefix3          = "../tests/ssl/group-with-intermediate"
	// TestCACertFilename3      = "ca/ca.crt"
	// TestICACertFilename3     = "intermediate-ca/intermediate-ca.crt"
	// TestCertFilename3        = "acra-writer/acra-writer.crt"
	// TestRevokedCertFilename3 = "acra-writer-revoked/acra-writer-revoked.crt"
	// TestCRLFilename3         = "intermediate-ca/crl.pem"
	// TestOCSPCertFilename3    = "intermediate-ocsp-responder/intermediate-ocsp-responder.crt"
	// TestOCSPKeyFilename3     = "intermediate-ocsp-responder/intermediate-ocsp-responder.key"

	// Make sure you use either of these groups and don't mix their components
)

type TestCertGroup struct {
	prefix string

	ca             string
	intermediateCA string // may be empty (missing)

	validCert   string
	revokedCert string

	crl string

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

// func getTestCertGroup3(t *testing.T) TestCertGroup {
// 	validRawCerts, validVerifiedChains := getValidTestChain3(t)
// 	invalidRawCerts, invalidVerifiedChains := getInvalidTestChain3(t)
//
// 	return TestCertGroup{
// 		prefix:                TestCertPrefix3,
// 		ca:                    TestCACertFilename3,
// 		intermediateCA:        TestICACertFilename3,
// 		validCert:             TestCertFilename3,
// 		revokedCert:           TestRevokedCertFilename3,
// 		crl:                   TestCRLFilename3,
// 		ocspCert:              TestOCSPCertFilename3,
// 		ocspKey:               TestOCSPKeyFilename3,
// 		validRawCerts:         validRawCerts,
// 		validVerifiedChains:   validVerifiedChains,
// 		invalidRawCerts:       invalidRawCerts,
// 		invalidVerifiedChains: invalidVerifiedChains,
// 	}
// }

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

func getTestCRL(t *testing.T, filename string) ([]byte, *pkix.CertificateList) {
	rawCRL, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("Cannot read CRL: %v\n", err)
	}

	crl, err := x509.ParseCRL(rawCRL)
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v\n", err)
	}

	return rawCRL, crl
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
	if len(paths) < 2 {
		t.Fatal("Certificate chain should contain at least two certificates\n")
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
			t.Fatalf("First certificate in chain (`%s`) should not be CA", cert.Subject.String())
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

// func getValidTestChain3(t *testing.T) ([][]byte, [][]*x509.Certificate) {
// 	return getTestChain(
// 		t,
// 		TestCertPrefix3,
// 		TestCertFilename3,
// 		TestICACertFilename3,
// 		TestCACertFilename3)
// }

func getInvalidTestChain(t *testing.T) ([][]byte, [][]*x509.Certificate) {
	return getTestChain(
		t,
		TestCertPrefix,
		TestRevokedCertFilename,
		TestCACertFilename)
}

// func getInvalidTestChain3(t *testing.T) ([][]byte, [][]*x509.Certificate) {
// 	return getTestChain(
// 		t,
// 		TestCertPrefix3,
// 		TestRevokedCertFilename3,
// 		TestICACertFilename3,
// 		TestCACertFilename3)
// }

func TestCRLConfig(t *testing.T) {
	expectOk := func(url, fromCert string, cacheSize, cacheTime int) {
		config, err := NewCRLConfig(url, fromCert, cacheSize, cacheTime)
		if config == nil || err != nil {
			t.Logf("url=%v, fromCert=%v, cacheSize=%v, cacheTime=%v\n", url, fromCert, cacheSize, cacheTime)
			t.Logf("config=%v, err=%v\n", config, err)
			t.Fatal("Got `nil` result or unexpected error")
		}
	}

	expectErr := func(url, fromCert string, cacheSize, cacheTime int) {
		config, err := NewCRLConfig(url, fromCert, cacheSize, cacheTime)
		if config != nil || err == nil {
			t.Logf("url=%v, fromCert=%v, cacheSize=%v, cacheTime=%v\n", url, fromCert, cacheSize, cacheTime)
			t.Logf("config=%v, err=%v\n", config, err)
			t.Fatal("Got unexpected result or `nil` error")
		}
	}

	expectOk("", "use", 1, 5)
	expectOk("", "ignore", 1, 5)
	expectOk("http://127.0.0.1/main_crl.pem", "use", 1, 5)
	expectOk("", "use", 1, 0)
	expectOk("", "use", 1, 1)
	expectOk("", "use", 1, 300)

	expectErr("htt://invalid url", "use", 1, 5)
	expectErr("", "IgNoRe", 1, 5)
	expectErr("", "use", 1, -1)
	expectErr("", "use", 1, -10)
	expectErr("", "use", 1, 301)
	expectErr("", "use", 1, 9000)
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

	fetchedCRL, err := crlClient.Fetch(url)
	if err != nil {
		t.Fatalf("Unexpected error durlng reading %s: %v\n", url, err)
	}

	if !bytes.Equal(rawCRL, fetchedCRL) {
		t.Fatal("CRLClient returned mismatched data\n")
	}

	//
	// Test with invalid URL (i.e. when server returns 404 not found or any other error)
	//
	url = fmt.Sprintf("http://%s/wrong_filename.pem", addr)

	fetchedCRL, err = crlClient.Fetch(url)
	if err == nil {
		t.Fatal("Unexpected success durlng reading CRL from wrong URL\n")
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

	fetchedCRL, err := crlClient.Fetch(url)
	if err != nil {
		t.Fatalf("Unexpected error durlng reading %s: %v\n", url, err)
	}

	if !bytes.Equal(rawCRL, fetchedCRL) {
		t.Fatal("CRLClient returned mismatched data\n")
	}
}

func TestLRUCRLCache(t *testing.T) {
	// Same as TestDefaultCRLCache, but with *pkix.CertificateList instead of []byte as value
	cache := NewLRUCRLCache(4)

	_, crl := getTestCRL(t, path.Join(TestCertPrefix, TestCRLFilename))

	cacheItem := &CRLCacheItem{Fetched: time.Now(), CRL: *crl}

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

func testDefaultCRLVerifierWithGroup(t *testing.T, certGroup TestCertGroup) {
	rawCRL, _ := getTestCRL(t, path.Join(certGroup.prefix, certGroup.crl))

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

	crlConfig := CRLConfig{url: url, fromCert: crlFromCertIgnore}
	crlVerifier := DefaultCRLVerifier{Config: crlConfig, Client: NewDefaultCRLClient(), Cache: NewLRUCRLCache(16)}

	// Test valid certificate chain

	err := crlVerifier.Verify(certGroup.validRawCerts, certGroup.validVerifiedChains)
	if err != nil {
		t.Fatalf("Unexpected error for valid certificate: %v\n", err)
	}

	// Test invalid certificate chain that contains revoked certificate

	err = crlVerifier.Verify(certGroup.invalidRawCerts, certGroup.invalidVerifiedChains)
	if err == nil {
		t.Fatal("Unexpected success when verifying revoked certificate\n")
	}
	if err != ErrCertWasRevoked {
		t.Logf("Verify error: %v\n", err)
		t.Fatalf("Expected error: %d\n", ErrCertWasRevoked)
	}
	t.Logf("(Expected) verify error: %v\n", err)
}

func TestDefaultCRLVerifier(t *testing.T) {
	testDefaultCRLVerifierWithGroup(t, getTestCertGroup(t))
	// testDefaultCRLVerifierWithGroup(t, getTestCertGroup3(t))
}
