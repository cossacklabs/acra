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
	"strings"
	"testing"
	"time"
)

// Defined in crl_test.go:
//   func getTestHTTPServer(t *testing.T, mux *http.ServeMux) (*http.Server, string)
//   func pemToX509Cert(data []byte) (*x509.Certificate, error)
//   func getInvalidTestChain(t *testing.T) ([][]byte, [][]*x509.Certificate)
//   func getValidTestChain(t *testing.T) ([][]byte, [][]*x509.Certificate)

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
	// TODO: allow many issuers, currently all known certs should be signed by a single issuer
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
			t.Log("No Content-Type header in request")
			res.WriteHeader(400)
			return
		}

		if len(contentType) > 1 || contentType[0] != "application/ocsp-request" {
			t.Log("Content-Type != application/ocsp-request")
			res.WriteHeader(400)
			return
		}

		rawOCSPRequest := make([]byte, 1024*16)
		n, err := req.Body.Read(rawOCSPRequest)
		if err != nil && err.Error() != "EOF" {
			t.Logf("Cannot read the request: %v", err)
			res.WriteHeader(400)
			return
		}

		ocspRequest, err := ocsp.ParseRequest(rawOCSPRequest[:n])
		if err != nil {
			t.Logf("Cannot parse the request (%d bytes)", len(rawOCSPRequest))
			res.WriteHeader(400)
			return
		}

		t.Logf("Read %d bytes OCSP request", n)

		res.WriteHeader(200)
		res.Header().Add("Content-Type", "application/ocsp-response")

		template := ocsp.Response{
			Status:       ocsp.Unknown,
			SerialNumber: ocspRequest.SerialNumber,
			IssuerHash:   crypto.SHA256,
		}

		for _, testCase := range config.testCases {
			if ocspRequest.SerialNumber.Cmp(testCase.cert.SerialNumber) == 0 {
				switch testCase.expectedStatus {
				case ocsp.Good:
					t.Logf("Requested certificate 0x%s is valid", ocspRequest.SerialNumber.Text(16))
					template.Status = ocsp.Good
				case ocsp.Revoked:
					t.Logf("Requested certificate 0x%s was revoked", ocspRequest.SerialNumber.Text(16))
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
			t.Fatalf("Cannot create OCSP response: %v", err)
		}
		n, err = res.Write(response)
		if err != nil {
			t.Fatalf("Cannot write OCSP response: %v", err)
		}

		t.Logf("Wrote %d bytes OCSP response", n)
	})

	httpServer, addr := getTestHTTPServer(t, mux)

	return httpServer, addr
}

type ocspTestCase struct {
	issuer         *x509.Certificate
	cert           *x509.Certificate
	expectedStatus int
}

func getOCSPTestCase(t *testing.T, prefix string, expectedStatus int) *ocspTestCase {
	// Issuer (and root CA)
	rawIssuer := getTestCACert()
	issuer, err := pemToX509Cert(rawIssuer)
	if err != nil {
		t.Fatalf("Error while parsing CA cert: %v", err)
	}

	// The certificate itself
	filename := prefix + ".crt"
	rawCert, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("Error while reading %s: %v", filename, err)
	}
	cert, err := pemToX509Cert(rawCert)
	if err != nil {
		t.Fatalf("Error while parsing cert: %v", err)
	}

	return &ocspTestCase{
		issuer,
		cert,
		expectedStatus,
	}
}

func getTestOCSPCertAndKey(t *testing.T, prefix string) (*x509.Certificate, crypto.Signer) {
	// Read the certificate
	filename := prefix + ".crt"
	rawCert, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("Cannot read OCSP certificate at %s: %v", filename, err)
	}
	cert, err := pemToX509Cert(rawCert)
	if err != nil {
		t.Fatalf("Cannot parse OCSP certificate at %s: %v", filename, err)
	}

	// Read the corresponding key
	filename = prefix + ".key"
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("Cannot read OCSP private key at %s: %v", filename, err)
	}
	priv, err := pemToRsaPrivateKey(data)
	if err != nil {
		t.Fatalf("Cannot parse OCSP private key at %s: %v", filename, err)
	}

	return cert, priv
}

func TestDefaultOCSPClient(t *testing.T) {
	goodData := getOCSPTestCase(t, "../tests/ssl/acra-writer/acra-writer", ocsp.Good)
	revokedData := getOCSPTestCase(t, "../tests/ssl/acra-writer-revoked/acra-writer-revoked", ocsp.Revoked)
	ocspCertificate, ocspSigningKey := getTestOCSPCertAndKey(t, "../tests/ssl/ocsp/ocsp")

	ocspServerConfig := ocspServerConfig{
		issuerCert:    goodData.issuer,
		responderCert: ocspCertificate,
		responderKey:  ocspSigningKey,
		testCases:     []*ocspTestCase{goodData, revokedData},
	}

	ocspServer, addr := getTestOCSPServer(t, ocspServerConfig)
	defer ocspServer.Close()

	ocspClient := DefaultOCSPClient{}

	uri := fmt.Sprintf("http://%s", addr)

	checkCase := func(t *testing.T, data *ocspTestCase) {
		ocspResponse, err := ocspClient.Query(data.cert.Subject.CommonName, data.cert, ocspServerConfig.responderCert, uri)
		if err != nil {
			t.Fatalf("Unexpected error during reading %s: %v", uri, err)
		}

		if data.cert.SerialNumber.Cmp(ocspResponse.SerialNumber) != 0 {
			t.Fatalf("OCSPClient returned response with wrong certificate S/N")
		}

		if ocspResponse.Status != data.expectedStatus {
			t.Fatalf("Expected status %d, received %d", data.expectedStatus, ocspResponse.Status)
		}
	}

	// Test with valid certificate
	checkCase(t, goodData)

	// Test with revoked certificate
	checkCase(t, revokedData)
}

func testWithConfigAndValidChain(t *testing.T, ocspConfig *OCSPConfig, rawCerts [][]byte, verifiedChains [][]*x509.Certificate) {
	ocspClient := DefaultOCSPClient{}

	ocspVerifier := DefaultOCSPVerifier{Config: *ocspConfig, Client: ocspClient}

	err := ocspVerifier.Verify(rawCerts, verifiedChains)
	if err != nil {
		t.Fatalf("Unexpected error for valid certificate: %v", err)
	}
}

func testWithConfigAndRevokedChain(t *testing.T, ocspConfig *OCSPConfig, rawCerts [][]byte, verifiedChains [][]*x509.Certificate) {
	ocspClient := DefaultOCSPClient{}

	ocspVerifier := DefaultOCSPVerifier{Config: *ocspConfig, Client: ocspClient}

	err := ocspVerifier.Verify(rawCerts, verifiedChains)
	if err == nil {
		t.Fatal("Unexpected success when verifying revoked certificate")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Logf("Verify error: %v", err)
		t.Fatalf("Error does not contain 'revoked'")
	}
	t.Logf("(Expected) verify error: %v", err)
}

func TestDefaultOCSPVerifier(t *testing.T) {
	goodData := getOCSPTestCase(t, "../tests/ssl/acra-writer/acra-writer", ocsp.Good)
	revokedData := getOCSPTestCase(t, "../tests/ssl/acra-writer-revoked/acra-writer-revoked", ocsp.Revoked)
	// TODO switch CA cert -> OCSP responder cert as soon as OCSPVerifier can handle that
	ocspCertificate, ocspSigningKey := getTestOCSPCertAndKey(t, "../tests/ssl/ca/ca")

	ocspServerConfig := ocspServerConfig{
		issuerCert:    goodData.issuer,
		responderCert: ocspCertificate,
		responderKey:  ocspSigningKey,
		testCases:     []*ocspTestCase{goodData, revokedData},
	}

	ocspServer, addr := getTestOCSPServer(t, ocspServerConfig)
	defer ocspServer.Close()

	uri := fmt.Sprintf("http://%s", addr)

	// TODO generate these chains by reading files, like getOCSPTestCase() does
	validRawCerts, validVerifiedChains := getValidTestChain(t)
	invalidRawCerts, invalidVerifiedChains := getInvalidTestChain(t)

	//
	// Test with default config, certificates contain OCSP server inside
	//
	ocspConfig, err := NewOCSPConfig("", ocspRequiredYesStr, ocspFromCertUseStr, false)
	if err != nil {
		t.Fatalf("Failed to create OCSPConfig: %v", err)
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
		t.Fatalf("Failed to create OCSPConfig: %v", err)
	}

	validVerifiedChains[0][0].OCSPServer = []string{}
	invalidVerifiedChains[0][0].OCSPServer = []string{}

	testWithConfigAndValidChain(t, ocspConfig, validRawCerts, validVerifiedChains)
	testWithConfigAndRevokedChain(t, ocspConfig, invalidRawCerts, invalidVerifiedChains)
}
