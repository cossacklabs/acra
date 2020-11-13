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
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func getTestCACert() []byte {
	// tests/ssl/ca/ca.crt
	return []byte(`
-----BEGIN CERTIFICATE-----
MIID4TCCAsmgAwIBAgIUQ24MW+Sq36AfAUy6Rq1hRYHI7CgwDQYJKoZIhvcNAQEL
BQAwdDELMAkGA1UEBhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9u
ZG9uMRgwFgYDVQQKDA9HbG9iYWwgU2VjdXJpdHkxCzAJBgNVBAsMAklUMRwwGgYD
VQQDDBNUZXN0IENBIGNlcnRpZmljYXRlMCAXDTIwMDkyMjE2MDUzNFoYDzIwNzAw
OTEwMTYwNTM0WjB0MQswCQYDVQQGEwJHQjEPMA0GA1UECAwGTG9uZG9uMQ8wDQYD
VQQHDAZMb25kb24xGDAWBgNVBAoMD0dsb2JhbCBTZWN1cml0eTELMAkGA1UECwwC
SVQxHDAaBgNVBAMME1Rlc3QgQ0EgY2VydGlmaWNhdGUwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC+EmCoONyAvjAvWwqxVTaUCkPDAzo2f67xg+hppOJz
JuBOXed5zBvfStGITIWvCzStrSK6PSLE6J6ZM1FNjplJaD/uRORRWA83SAqqOszj
yDz+Qds7p/zsqEu9maBWO3MK0FLl9cENh4cH+XhM/qs8CXsGpDz6HMDUgydbRCdk
dlUBs+kwK4amjhKe3mWbJSKdidqYA/NHzYTuWISYydKi4zGpRxuo3Ajrc/OuztR4
ZroZjpFOQILnY2q9FwVWRR+3lsZ8EJVGB2TTCMnOVnB03HdGVsQpxgon3fMeQyd6
vDaHnIw48XUhBPaVoasr7iVInR9xkZq/HloXSHqZhpgLAgMBAAGjaTBnMA8GA1Ud
EwEB/wQFMAMBAf8wFAYDVR0RBA0wC4IJbG9jYWxob3N0MB0GA1UdDgQWBBTpWFDI
5iVh4tayUVshvUm7g6BKqDAfBgNVHSMEGDAWgBTpWFDI5iVh4tayUVshvUm7g6BK
qDANBgkqhkiG9w0BAQsFAAOCAQEABqiGW6PA4MEECFmKu82YrAQrVN20696pnIbJ
PTLNoLdagj4tXBcRXO87g9enfuJfXAL26FJHvfnwzDIkHkIi10oBJZLjQ/6BQwR+
jDSEXeRfDajA6LhO5iDRp9C/DvfzcnpW6yIOE+ugdrroCHGk5k5abjwGISuobJgT
czDf+qWpAGEp1JoVPt4QaCKnFwNbXJa37XfyQajP7EVZlUHKr4FWcaNd2ZhzTVMt
QlMzv5Dqc7CBT7a1+aLtuHEX1BdZRBdNf9Owv7DvbiJO3dMq29tr+RGyj8jFLvi7
CUW9vw/S1rYOsG+tgdQc6Wpzj3kupRdfwDWT25NYMyWdV5wQ6A==
-----END CERTIFICATE-----
`)
}

func getTestValidCert() []byte {
	// tests/ssl/acra-writer/acra-writer.crt
	return []byte(`
-----BEGIN CERTIFICATE-----
MIIEHjCCAwagAwIBAgIUB+oHR1yF7FVJs0RCGAhep2owHU0wDQYJKoZIhvcNAQEL
BQAwdDELMAkGA1UEBhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9u
ZG9uMRgwFgYDVQQKDA9HbG9iYWwgU2VjdXJpdHkxCzAJBgNVBAsMAklUMRwwGgYD
VQQDDBNUZXN0IENBIGNlcnRpZmljYXRlMCAXDTIwMTAyNjIzMjcwNVoYDzIwNzAx
MDE0MjMyNzA1WjCBhDELMAkGA1UEBhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0G
A1UEBwwGTG9uZG9uMRgwFgYDVQQKDA9HbG9iYWwgU2VjdXJpdHkxCzAJBgNVBAsM
AklUMSwwKgYDVQQDDCNUZXN0IGxlYWYgY2VydGlmaWNhdGUgKGFjcmEtd3JpdGVy
KTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALhg5arU9qD7PyO6ly8n
UIycMjI6Nxwp104xM/Zuz+7pzhJ1ob3eiTDvSS19/LJaG2fKBfNnYHVscwSKmFge
M15Y5ST+axz/w547/IQRe4sj+45B/kI6rYOUDz/e01NPXHXgWk4s+9shaYfOLtSB
HryRLpMRCSqnKTDMC8LdUDVt2ZgzCKhbr/6wBkiu07DxFn9e4NhS5DtF9n+7fzN5
ObtJ33MqiQIvBwlIg2Iphi/fsJ20ctogez6RDyPqchiGBjnb2lSYIWVIdaY/1vzb
fVuWn1p/hpxjmVZ7AnkwQMU4/dYjXEMZHIBtBnkg5GamGbh0Ky96i//Tu9exKvi+
1BsCAwEAAaOBlDCBkTAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAUBgNVHREEDTAL
gglsb2NhbGhvc3QwMQYIKwYBBQUHAQEEJTAjMCEGCCsGAQUFBzABhhVodHRwOi8v
MTI3LjAuMC4xOjg4ODgwLgYDVR0fBCcwJTAjoCGgH4YdaHR0cDovLzEyNy4wLjAu
MTo4ODg5L2NybC5wZW0wDQYJKoZIhvcNAQELBQADggEBADyAgpCkgVtEQ7S6NkMf
sBN68Gm2u2iJTvER2dhL8ZwGFTn0suw4aJbZtyPv4RNzUIzcSPER8/almZBh5Nlf
EmIvZhdslE3p2T0hojIZyCgpQgX6WRYmiGndXkKFNjUQznvqMQxm/r1twpPjlLR3
GxMnLuYDoZdnY7dImiCKPJkp0Pssenv//s/Z4uOesDhCIY4/zNp5YrYLr6hgA5lz
mvTUi9T6U8ILTegH7vL0hBv38b0xbJW0EoHz9bsi8zc2xCkir5jl7mOUaqbdFbtj
mcxTd8MMhQkqLY085J0ITFAHlvFjc4vXIZFQsKL8lakCRAOy7S82EiP69bOngo2s
n08=
-----END CERTIFICATE-----
`)
}

func getTestExpiredCert() []byte {
	// tests/ssl/acra-writer-revoked/acra-writer-revoked.crt
	return []byte(`
-----BEGIN CERTIFICATE-----
MIIEJjCCAw6gAwIBAgIUB+oHR1yF7FVJs0RCGAhep2owHU4wDQYJKoZIhvcNAQEL
BQAwdDELMAkGA1UEBhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9u
ZG9uMRgwFgYDVQQKDA9HbG9iYWwgU2VjdXJpdHkxCzAJBgNVBAsMAklUMRwwGgYD
VQQDDBNUZXN0IENBIGNlcnRpZmljYXRlMCAXDTIwMTAyNjIzMjcwNVoYDzIwNzAx
MDE0MjMyNzA1WjCBjDELMAkGA1UEBhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0G
A1UEBwwGTG9uZG9uMRgwFgYDVQQKDA9HbG9iYWwgU2VjdXJpdHkxCzAJBgNVBAsM
AklUMTQwMgYDVQQDDCtUZXN0IGxlYWYgY2VydGlmaWNhdGUgKGFjcmEtd3JpdGVy
LXJldm9rZWQpMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwYeEHPae
eZmQTn0XVbk7A4cokbF5aNg2mqNfgLDPBScEW6iN0Jm0/61JLDU67TGG0Lkan3qZ
51p+V8CW+geG8gWcHRKHOHUsaZQhkO94niFD2rTJclbJfBpza/sIdji11lmH5oOi
uzvBbX+4BtopierZdEXysa3WoFpM7rIxryOYeXegDjiDFqY7RmZvs9cD9hB+SDaX
W7whTRh8jFWOmGVEAq4YbiqbkfaFEX+8YrFoAjl4zHFlXfE3K7Wvx/WxGYuS50+4
4Wofkd6afnVggqWli3gLn/iYLjbog94vYJ0CSBf13NfYn8frMa01O9GGHsuShjNJ
MDt+/ZfPoHPVmQIDAQABo4GUMIGRMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgXgMBQG
A1UdEQQNMAuCCWxvY2FsaG9zdDAxBggrBgEFBQcBAQQlMCMwIQYIKwYBBQUHMAGG
FWh0dHA6Ly8xMjcuMC4wLjE6ODg4ODAuBgNVHR8EJzAlMCOgIaAfhh1odHRwOi8v
MTI3LjAuMC4xOjg4ODkvY3JsLnBlbTANBgkqhkiG9w0BAQsFAAOCAQEAH4yh4kUT
wAxm7cKNu73hOGwz9HFswp44jpAl4q9/kJHkA/ycITFbHEPKsruWfqLk7vxp7kgW
8Fv+qMyP5b0njDtAUWQuV8gn+DRQzPun8scG0kGJQb24ZQ4nWEPFm42H/roYv47B
7y7cYmnycP9c4oCaQMdJ29w4bdaC9SHZdQW0W57UkmelVjFU00odxia5O7VhKRkP
FC+mY9/+xkj2aDvunWLHwE4wXSzrFpOkGqNPpRU47HNO3K3giRTZXtKCap61J55B
W8Q1chrNalbgBuYfsbtVlCEoVuzPmkjGzJIHASk8NNo3jQ7EgQJUbff8d1MZwa2f
k5rkNiHTxPfguQ==
-----END CERTIFICATE-----
`)
}

func getTestCRL() []byte {
	// x509.ParseCRL() that is called inside CRL verifier is very fragile
	// and will return error because of \n on start, that's why this func
	// looks a little bit different from getTest*Cert()

	// tests/ssl/crl.pem
	return []byte(`-----BEGIN X509 CRL-----
MIIB4zCBzDANBgkqhkiG9w0BAQsFADB0MQswCQYDVQQGEwJHQjEPMA0GA1UECAwG
TG9uZG9uMQ8wDQYDVQQHDAZMb25kb24xGDAWBgNVBAoMD0dsb2JhbCBTZWN1cml0
eTELMAkGA1UECwwCSVQxHDAaBgNVBAMME1Rlc3QgQ0EgY2VydGlmaWNhdGUXDTIw
MTAyNjIzMjcwNloXDTIwMTEyNTIzMjcwNlowJzAlAhQH6gdHXIXsVUmzREIYCF6n
ajAdThcNMjAxMDI2MjMyNzA2WjANBgkqhkiG9w0BAQsFAAOCAQEAKKJ56Ba7bOqE
R8LFhfSwqqzGxVdPfDOu3d14cpRC3PJSLcyfLh+YA8Rkveed7Ee1RGaGjXrXTiZm
p44CQcslUFoFGdONVTzTAamCphOiLh/LZB65d2dWo1WwOfsLwwaE+KTk+99+Ug/j
EgiyuOwoyFqONlaDj4Z2PUC/mKmPuI1QJ9WB43oL8cDxPuOtJp0z2NEz0ZDl1pu6
ghaEHc7lPDBmCOOGYneqEtfAi/wzMzKEdeXxV9s3MBWsXKfdrwsQc2pjLuH+K/wv
aY3BPTUA7sZLJGFvsE2fh9yi1TsyKs4hsboS6FldZdXBnD/0ZqUnFy/KQ4t3LwH5
L6zfD+wegQ==
-----END X509 CRL-----`)
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

	// Give the server time to start, otherwise this test will fail sometimes
	time.Sleep(time.Millisecond * 100)

	return httpServer, addr
}

func getValidTestChain(t *testing.T) ([][]byte, [][]*x509.Certificate) {
	validRawCerts := [][]byte{}
	validRawCerts = append(validRawCerts, getTestValidCert())
	validRawCerts = append(validRawCerts, getTestCACert())

	validVerifiedChains := [][]*x509.Certificate{}
	validVerifiedChains = append(validVerifiedChains, []*x509.Certificate{})
	cert, err := pemToX509Cert(validRawCerts[0])
	if err != nil {
		t.Fatalf("Failed to parse test PEM certificate: %v", err)
	}
	validVerifiedChains[0] = append(validVerifiedChains[0], cert)
	cert, err = pemToX509Cert(validRawCerts[1])
	if err != nil {
		t.Fatalf("Failed to parse test PEM certificate: %v", err)
	}
	validVerifiedChains[0] = append(validVerifiedChains[0], cert)

	t.Logf("validVerifiedChains[0][0].Subject = %s", validVerifiedChains[0][0].Subject.String())
	t.Logf("validVerifiedChains[0][1].Subject = %s", validVerifiedChains[0][1].Subject.String())
	if err = validVerifiedChains[0][0].CheckSignatureFrom(validVerifiedChains[0][1]); err != nil {
		t.Fatalf("Cert was not signed by CA: %v", err)
	}

	return validRawCerts, validVerifiedChains
}

func getInvalidTestChain(t *testing.T) ([][]byte, [][]*x509.Certificate) {
	invalidRawCerts := [][]byte{}
	invalidRawCerts = append(invalidRawCerts, getTestExpiredCert())
	invalidRawCerts = append(invalidRawCerts, getTestCACert())

	invalidVerifiedChains := [][]*x509.Certificate{}
	invalidVerifiedChains = append(invalidVerifiedChains, []*x509.Certificate{})
	cert, err := pemToX509Cert(invalidRawCerts[0])
	if err != nil {
		t.Fatalf("Failed to parse test PEM certificate: %v", err)
	}
	invalidVerifiedChains[0] = append(invalidVerifiedChains[0], cert)
	cert, err = pemToX509Cert(invalidRawCerts[1])
	if err != nil {
		t.Fatalf("Failed to parse test PEM certificate: %v", err)
	}
	invalidVerifiedChains[0] = append(invalidVerifiedChains[0], cert)

	t.Logf("invalidVerifiedChains[0][0].Subject = %s", invalidVerifiedChains[0][0].Subject.String())
	t.Logf("invalidVerifiedChains[0][1].Subject = %s", invalidVerifiedChains[0][1].Subject.String())
	if err = invalidVerifiedChains[0][0].CheckSignatureFrom(invalidVerifiedChains[0][1]); err != nil {
		t.Fatalf("Cert was not signed by CA: %v", err)
	}

	return invalidRawCerts, invalidVerifiedChains
}

func TestDefaultCRLClientHTTP(t *testing.T) {
	crl := getTestCRL()

	mux := http.NewServeMux()
	mux.HandleFunc("/test_crl.pem", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(200)
		res.Header().Add("Content-Type", "application/pem-certificate-chain")
		res.Write(crl)
	})

	httpServer, addr := getTestHTTPServer(t, mux)
	defer httpServer.Close()

	crlClient := NewDefaultCRLClient()

	//
	// Test with valid URI
	//
	uri := fmt.Sprintf("http://%s/test_crl.pem", addr)

	fetchedCRL, err := crlClient.Fetch(uri)
	if err != nil {
		t.Fatalf("Unexpected error during reading %s: %v", uri, err)
	}

	if !bytes.Equal(crl, fetchedCRL) {
		t.Fatalf("CRLClient returned mismatched data")
	}

	//
	// Test with invalid URI (i.e. when server returns 404 not found or any other error)
	//
	uri = fmt.Sprintf("http://%s/wrong_filename.pem", addr)

	fetchedCRL, err = crlClient.Fetch(uri)
	if err == nil {
		t.Fatalf("Unexpected success during reading CRL from wrong URI")
	} else {
		t.Logf("(Expected) fetch error: %v", err)
	}
}

func TestDefaultCRLClientFile(t *testing.T) {
	crl := getTestCRL()

	file, err := ioutil.TempFile("", "go_test_crl_*.pem")
	if err != nil {
		t.Fatalf("Cannot create temporary file to store CRL: %v", err)
	}
	defer os.Remove(file.Name())

	_, err = file.Write(crl)
	if err != nil {
		t.Fatalf("Cannot write CRL to temporary file: %v", err)
	}

	crlClient := NewDefaultCRLClient()

	uri := fmt.Sprintf("file://%s", file.Name())

	fetchedCRL, err := crlClient.Fetch(uri)
	if err != nil {
		t.Fatalf("Unexpected error during reading %s: %v", uri, err)
	}

	if !bytes.Equal(crl, fetchedCRL) {
		t.Fatalf("CRLClient returned mismatched data")
	}
}

func TestDefaultCRLCache(t *testing.T) {
	cache := DefaultCRLCache{}

	// we don't expect to see any items in cache when it's created
	data, err := cache.Get("test1")
	if data != nil {
		t.Fatalf("Unexpected data while reading empty cache")
	}
	if err == nil {
		t.Fatalf("No expected error while reading empty cache")
	}

	// let's insert something
	cache.Put("test1", []byte(`--- insert CRL content here ---`))
	data, err = cache.Get("test1")
	if data == nil {
		t.Fatalf("Unexpected fail while reading recently inserted cache item")
	}
	if err != nil {
		t.Fatalf("Unexpected error while reading recently inserted cache item")
	}

	// and test removal
	err = cache.Remove("test1")
	if err != nil {
		t.Fatalf("Unexpected error while removing recently inserted cache item")
	}
	data, err = cache.Get("test1")
	if data != nil {
		t.Fatalf("Unexpected data while reading removed cache item")
	}
	if err == nil {
		t.Fatalf("Unexpected error while reading removed cache item")
	}
}

func TestLRUParsedCRLCache(t *testing.T) {
	// Same as TestDefaultCRLCache, but with *pkix.CertificateList instead of []byte as value
	cache := NewLRUParsedCRLCache(4)

	crl, err := x509.ParseCRL(getTestCRL())
	if err != nil {
		t.Fatal("Failed to parse test CRL")
	}

	// we don't expect to see any items in cache when it's created
	cachedCRL, err := cache.Get("test1")
	if cachedCRL != nil {
		t.Fatalf("Unexpected data while reading empty cache")
	}
	if err == nil {
		t.Fatalf("No expected error while reading empty cache")
	}

	// let's insert something
	cache.Put("test1", crl)
	cachedCRL, err = cache.Get("test1")
	if cachedCRL == nil {
		t.Fatalf("Unexpected fail while reading recently inserted cache item")
	}
	if err != nil {
		t.Fatalf("Unexpected error while reading recently inserted cache item")
	}

	// and test removal
	err = cache.Remove("test1")
	if err != nil {
		t.Fatalf("Unexpected error while removing recently inserted cache item")
	}
	cachedCRL, err = cache.Get("test1")
	if cachedCRL != nil {
		t.Fatalf("Unexpected data while reading removed cache item")
	}
	if err == nil {
		t.Fatalf("Unexpected error while reading removed cache item")
	}
}

func TestDefaultCRLVerifier(t *testing.T) {
	crlConfig := CRLConfig{uri: "http://127.0.0.1:8889/crl.pem", fromCert: crlFromCertIgnore}
	crlVerifier := DefaultCRLVerifier{Config: crlConfig, Client: NewDefaultCRLClient(), Cache: &DefaultCRLCache{}, ParsedCache: NewLRUParsedCRLCache(16)}

	// Fool crlVerifier into thinking the CRL is already in cache to avoid performing requests.
	// CRLCache and CRLClient are tested separately anyway.
	crlVerifier.Cache.Put("http://127.0.0.1:8889/crl.pem", getTestCRL())

	//
	// Test valid certificate chain
	//
	validRawCerts, validVerifiedChains := getValidTestChain(t)

	err := crlVerifier.Verify(validRawCerts, validVerifiedChains)
	if err != nil {
		t.Fatalf("Unexpected error for valid certificate: %v", err)
	}

	//
	// Test invalid certificate chain that contains revoked certificate
	//
	invalidRawCerts, invalidVerifiedChains := getInvalidTestChain(t)

	err = crlVerifier.Verify(invalidRawCerts, invalidVerifiedChains)
	if err == nil {
		t.Fatal("Unexpected success when verifying revoked certificate")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Logf("Verify error: %v", err)
		t.Fatalf("Error does not contain 'revoked'")
	}
	t.Logf("(Expected) verify error: %v", err)
}
