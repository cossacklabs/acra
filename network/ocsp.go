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
	"crypto"
	"crypto/x509"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
	"net/url"
)

func isCertificateRevokedByOCSP(commonName string, clientCert, issuerCert *x509.Certificate, ocspServer string) (bool, error) {
	opts := &ocsp.RequestOptions{Hash: crypto.SHA256}
	buffer, err := ocsp.CreateRequest(clientCert, issuerCert, opts)
	if err != nil {
		return false, err
	}
	httpRequest, err := http.NewRequest(http.MethodPost, ocspServer, bytes.NewBuffer(buffer))
	if err != nil {
		return false, err
	}
	ocspUrl, err := url.Parse(ocspServer)
	if err != nil {
		return false, err
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspUrl.Host)
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return false, err
	}
	defer httpResponse.Body.Close()
	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return false, err
	}
	ocspResponse, err := ocsp.ParseResponse(output, issuerCert)
	if err != nil {
		return false, err
	}
	if ocspResponse.Status == ocsp.Revoked {
		return true, nil
	} else {
		return false, nil
	}
}
