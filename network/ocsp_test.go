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
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
	"path"
	"testing"
	"time"
)

// Defined in crl_test.go:
//   func getTestHTTPServer(t *testing.T, mux *http.ServeMux) (*http.Server, string)
//   func pemToX509Cert(data []byte) (*x509.Certificate, error)
//   func getValidTestChain(t *testing.T) ([][]byte, [][]*x509.Certificate)
//   func getInvalidTestChain(t *testing.T) ([][]byte, [][]*x509.Certificate)
//   Test* constants

// Convert PEM-encoded private key into DER and parse it into rsa.PrivateKey
func pemToRsaPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	der, _ := pem.Decode(data)
	if der == nil {
		return nil, errors.New("Failed to decode PEM")
	}

	switch der.Type {
	case "RSA PRIVATE KEY":
		rsaKey, err := x509.ParsePKCS1PrivateKey(der.Bytes)
		if err != nil {
			return nil, err
		}

		return rsaKey, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(der.Bytes)
		if err != nil {
			return nil, err
		}

		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("Cannot cast parsed key to RSA private key")
		}

		// TODO: handle ecdsa.PrivateKey and ed25519.PrivateKey as well, make this func return crypto.Signer

		return rsaKey, nil

	default:
		return nil, errors.New("Decoded DER block was not a private key")
	}
}

type ocspServerConfig struct {
	// Certificate of issuer
	issuerCert *x509.Certificate
	// Certificate of OCSP responder (may be different from issuer)
	responderCert *x509.Certificate
	// `priv' is used to sign OCSP responses
	responderKey crypto.Signer
	// List of known certificates
	testCases []*ocspTestCase
}

func getTestOCSPServer(t *testing.T, config ocspServerConfig) (*http.Server, string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		contentType, ok := req.Header["Content-Type"]
		if !ok {
			t.Log("No Content-Type header in request\n")
			res.WriteHeader(400)
			return
		}

		if len(contentType) > 1 || contentType[0] != "application/ocsp-request" {
			t.Log("Content-Type != application/ocsp-request\n")
			res.WriteHeader(400)
			return
		}

		rawOCSPRequest := make([]byte, 1024*16)
		n, err := req.Body.Read(rawOCSPRequest)
		if err != nil && err.Error() != "EOF" {
			t.Logf("Cannot read the request: %v\n", err)
			res.WriteHeader(400)
			return
		}

		ocspRequest, err := ocsp.ParseRequest(rawOCSPRequest[:n])
		if err != nil {
			t.Logf("Cannot parse the request (%d bytes)\n", len(rawOCSPRequest))
			res.WriteHeader(400)
			return
		}

		// t.Logf("Read %d bytes OCSP request\n", n)

		res.WriteHeader(200)
		res.Header().Add("Content-Type", "application/ocsp-response")

		template := ocsp.Response{
			Certificate:  config.responderCert,
			Status:       ocsp.Unknown,
			SerialNumber: ocspRequest.SerialNumber,
			IssuerHash:   crypto.SHA256,
		}

		// TODO check whether ocspRequest.IssuerKeyHash matches config.issuerCert.PublicKey somehow,
		//      return error of mismatch

		for _, testCase := range config.testCases {
			if ocspRequest.SerialNumber.Cmp(testCase.cert.SerialNumber) == 0 {
				switch testCase.expectedStatus {
				case ocsp.Good:
					t.Logf("Requested certificate 0x%s is valid\n", ocspRequest.SerialNumber.Text(16))
					template.Status = ocsp.Good
				case ocsp.Revoked:
					t.Logf("Requested certificate 0x%s was revoked\n", ocspRequest.SerialNumber.Text(16))
					template.Status = ocsp.Revoked
					// XXX is there a better way to tell the cert was revoked one min ago?
					template.RevokedAt = time.Now().Add(time.Second * time.Duration(-60))
					template.RevocationReason = ocsp.Unspecified
				}
				break
			}
		}

		response, err := ocsp.CreateResponse(config.issuerCert, config.responderCert, template, config.responderKey)
		if err != nil {
			t.Fatalf("Cannot create OCSP response: %v\n", err)
		}
		_, err = res.Write(response)
		if err != nil {
			t.Fatalf("Cannot write OCSP response: %v\n", err)
		}

		// t.Logf("Wrote %d bytes OCSP response\n", n)
	})

	httpServer, addr := getTestHTTPServer(t, mux)

	return httpServer, addr
}

type ocspTestCase struct {
	issuer         *x509.Certificate
	cert           *x509.Certificate
	expectedStatus int
}

func getOCSPTestCase(t *testing.T, prefix, certFilename, issuerFilename string, expectedStatus int) *ocspTestCase {
	// Issuer (and root CA)
	_, issuer := getTestCert(t, path.Join(prefix, issuerFilename))

	// The certificate itself
	_, cert := getTestCert(t, path.Join(prefix, certFilename))

	return &ocspTestCase{
		issuer,
		cert,
		expectedStatus,
	}
}

func getTestOCSPCertAndKey(t *testing.T, prefix, certFilename, keyFilename string) (*x509.Certificate, crypto.Signer) {
	// Read the certificate
	filename := path.Join(prefix, certFilename)
	rawCert, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("Cannot read OCSP certificate at %s: %v\n", filename, err)
	}
	cert, err := pemToX509Cert(rawCert)
	if err != nil {
		t.Fatalf("Cannot parse OCSP certificate at %s: %v\n", filename, err)
	}

	// Read the corresponding key
	filename = path.Join(prefix, keyFilename)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("Cannot read OCSP private key at %s: %v\n", filename, err)
	}
	priv, err := pemToRsaPrivateKey(data)
	if err != nil {
		t.Fatalf("Cannot parse OCSP private key at %s: %v\n", filename, err)
	}

	return cert, priv
}

func TestOCSPConfig(t *testing.T) {
	expectOk := func(uri, required, fromCert string, checkWholeChain bool) {
		config, err := NewOCSPConfig(uri, required, fromCert, checkWholeChain)
		if config == nil || err != nil {
			t.Logf("uri=%v, required=%v, fromCert=%v, checkWholeChain=%v\n", uri, required, fromCert, checkWholeChain)
			t.Logf("config=%v, err=%v\n", config, err)
			t.Fatal("Got `nil` result or unexpected error")
		}
	}

	expectErr := func(uri, required, fromCert string, checkWholeChain bool) {
		config, err := NewOCSPConfig(uri, required, fromCert, checkWholeChain)
		if config != nil || err == nil {
			t.Logf("uri=%v, required=%v, fromCert=%v, checkWholeChain=%v\n", uri, required, fromCert, checkWholeChain)
			t.Logf("config=%v, err=%v\n", config, err)
			t.Fatal("Got unexpected result or `nil` error")
		}
	}

	expectOk("", "denyUnknown", "use", false)
	expectOk("http://127.0.0.1", "denyUnknown", "use", false)
	expectOk("http://127.0.0.1:12345", "denyUnknown", "use", false)
	expectOk("", "denyUnknown", "ignore", false)
	expectOk("http://127.0.0.1", "all", "use", false)
	expectOk("", "allowUnknown", "ignore", false)
	expectOk("", "allowUnknown", "trust", false)
	expectOk("", "allowUnknown", "prefer", false)

	expectErr("http://random text", "denyUnknown", "use", false)
	expectErr("http://127.0.0.1", "one two three", "use", false)
	expectErr("", "all", "use", false)
	expectErr("", "all", "invalid value", false)
}

func testDefaultOCSPClientWithGroup(t *testing.T, certGroup TestCertGroup) {
	goodData := &ocspTestCase{
		cert:           certGroup.validVerifiedChains[0][0],
		issuer:         certGroup.validVerifiedChains[0][1],
		expectedStatus: ocsp.Good,
	}

	revokedData := &ocspTestCase{
		cert:           certGroup.invalidVerifiedChains[0][0],
		issuer:         certGroup.invalidVerifiedChains[0][1],
		expectedStatus: ocsp.Revoked,
	}

	ocspCertificate, ocspSigningKey := getTestOCSPCertAndKey(t, certGroup.prefix, certGroup.ocspCert, certGroup.ocspKey)

	ocspServerConfig := ocspServerConfig{
		issuerCert:    goodData.issuer,
		responderCert: ocspCertificate,
		responderKey:  ocspSigningKey,
		testCases: []*ocspTestCase{
			goodData,
			revokedData,
		},
	}

	ocspServer, addr := getTestOCSPServer(t, ocspServerConfig)
	defer ocspServer.Close()

	ocspClient := DefaultOCSPClient{}

	uri := fmt.Sprintf("http://%s", addr)

	checkCase := func(t *testing.T, data *ocspTestCase) {
		ocspResponse, err := ocspClient.Query(data.cert.Subject.CommonName, data.cert, ocspServerConfig.issuerCert, uri)
		if err != nil {
			t.Fatalf("Unexpected error during reading %s: %v\n", uri, err)
		}

		if data.cert.SerialNumber.Cmp(ocspResponse.SerialNumber) != 0 {
			t.Fatalf("OCSPClient returned response with wrong certificate S/N\n")
		}

		if ocspResponse.Status != data.expectedStatus {
			t.Fatalf("Expected status %d, received %d\n", data.expectedStatus, ocspResponse.Status)
		}
	}

	// Test with valid certificate
	checkCase(t, goodData)

	// Test with revoked certificate
	checkCase(t, revokedData)
}

func TestDefaultOCSPClient(t *testing.T) {
	testDefaultOCSPClientWithGroup(t, getTestCertGroup(t))
	// testDefaultOCSPClientWithGroup(t, getTestCertGroup3(t))
}

func testWithConfigAndValidChain(t *testing.T, ocspConfig *OCSPConfig, rawCerts [][]byte, verifiedChains [][]*x509.Certificate) {
	ocspClient := DefaultOCSPClient{}

	ocspVerifier := DefaultOCSPVerifier{Config: *ocspConfig, Client: ocspClient}

	err := ocspVerifier.Verify(rawCerts, verifiedChains)
	if err != nil {
		t.Fatalf("Unexpected error for valid certificate: %v\n", err)
	}
}

func testWithConfigAndRevokedChain(t *testing.T, ocspConfig *OCSPConfig, rawCerts [][]byte, verifiedChains [][]*x509.Certificate) {
	ocspClient := DefaultOCSPClient{}

	ocspVerifier := DefaultOCSPVerifier{Config: *ocspConfig, Client: ocspClient}

	err := ocspVerifier.Verify(rawCerts, verifiedChains)
	if err == nil {
		t.Fatal("Unexpected success when verifying revoked certificate\n")
	}
	if err != ErrCertWasRevoked {
		t.Logf("Verify error: %v\n", err)
		t.Fatalf("Expected error: %d\n", ErrCertWasRevoked)
	}
	t.Logf("(Expected) verify error: %v\n", err)
}

func testDefaultOCSPVerifierWithGroup(t *testing.T, certGroup TestCertGroup) {
	goodData := &ocspTestCase{
		cert:           certGroup.validVerifiedChains[0][0],
		issuer:         certGroup.validVerifiedChains[0][1],
		expectedStatus: ocsp.Good,
	}

	revokedData := &ocspTestCase{
		cert:           certGroup.invalidVerifiedChains[0][0],
		issuer:         certGroup.invalidVerifiedChains[0][1],
		expectedStatus: ocsp.Revoked,
	}

	ocspCertificate, ocspSigningKey := getTestOCSPCertAndKey(t, certGroup.prefix, certGroup.ocspCert, certGroup.ocspKey)

	ocspServerConfig := ocspServerConfig{
		issuerCert:    goodData.issuer,
		responderCert: ocspCertificate,
		responderKey:  ocspSigningKey,
		testCases: []*ocspTestCase{
			goodData,
			revokedData,
		},
	}

	ocspServer, addr := getTestOCSPServer(t, ocspServerConfig)
	defer ocspServer.Close()

	uri := fmt.Sprintf("http://%s", addr)

	validRawCerts, validVerifiedChains := certGroup.validRawCerts, certGroup.validVerifiedChains
	invalidRawCerts, invalidVerifiedChains := certGroup.invalidRawCerts, certGroup.invalidVerifiedChains

	//
	// Test with default config, certificates contain OCSP server inside
	//
	ocspConfig, err := NewOCSPConfig("", ocspRequiredYesStr, ocspFromCertUseStr, false)
	if err != nil {
		t.Fatalf("Failed to create OCSPConfig: %v\n", err)
	}

	validVerifiedChains[0][0].OCSPServer = []string{uri}
	invalidVerifiedChains[0][0].OCSPServer = []string{uri}

	testWithConfigAndValidChain(t, ocspConfig, validRawCerts, validVerifiedChains)
	testWithConfigAndRevokedChain(t, ocspConfig, invalidRawCerts, invalidVerifiedChains)

	//
	// Test with URI in config only
	//
	ocspConfig, err = NewOCSPConfig(uri, ocspRequiredYesStr, ocspFromCertUseStr, false)
	if err != nil {
		t.Fatalf("Failed to create OCSPConfig: %v\n", err)
	}

	validVerifiedChains[0][0].OCSPServer = []string{}
	invalidVerifiedChains[0][0].OCSPServer = []string{}

	testWithConfigAndValidChain(t, ocspConfig, validRawCerts, validVerifiedChains)
	testWithConfigAndRevokedChain(t, ocspConfig, invalidRawCerts, invalidVerifiedChains)
}

func TestDefaultOCSPVerifier(t *testing.T) {
	testDefaultOCSPVerifierWithGroup(t, getTestCertGroup(t))
	// testDefaultOCSPVerifierWithGroup(t, getTestCertGroup3(t))
}
