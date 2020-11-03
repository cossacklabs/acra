/*
Copyright 2016, Cossack Labs Limited

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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"time"
)

// allowedCipherSuits that set in default tls config
var allowedCipherSuits = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}

// TLSConnectionWrapper for wrapping connection into TLS encryption
type TLSConnectionWrapper struct {
	config   *tls.Config
	clientID []byte
}

// ErrEmptyTLSConfig if not TLS config found
var ErrEmptyTLSConfig = errors.New("empty TLS config")

var (
	tlsCA            string
	tlsKey           string
	tlsCert          string
	tlsAuthType      int
	tlsServerName    string
	tlsOcspUrl       string
	tlsOcspClientUrl string
	tlsOcspDbUrl     string
	tlsOcspRequired  string
	tlsOcspFromCert  string
	tlsCrlUrl        string
	tlsCrlFromCert   string
)

// RegisterTLSBaseArgs register CLI args tls_ca|tls_key|tls_cert|tls_auth|tls_ocsp_url|tls_ocsp_client_url|tls_ocsp_db_url|tls_ocsp_required|tls_ocsp_from_cert|tls_crl_url|tls_crl_from_cert which allow to get tls.Config by NewTLSConfigFromBaseArgs function
func RegisterTLSBaseArgs() {
	flag.StringVar(&tlsCA, "tls_ca", "", "Path to root certificate which will be used with system root certificates to validate peer's certificate")
	flag.StringVar(&tlsKey, "tls_key", "", "Path to private key that will be used for TLS connections")
	flag.StringVar(&tlsCert, "tls_cert", "", "Path to certificate")
	flag.IntVar(&tlsAuthType, "tls_auth", int(tls.RequireAndVerifyClientCert), "Set authentication mode that will be used in TLS connection. Values in range 0-4 that set auth type (https://golang.org/pkg/crypto/tls/#ClientAuthType). Default is tls.RequireAndVerifyClientCert")
	flag.StringVar(&tlsOcspUrl, "tls_ocsp_url", "", "OCSP service URL")
	flag.StringVar(&tlsOcspClientUrl, "tls_ocsp_client_url", "", "OCSP service URL, for client certificates only")
	flag.StringVar(&tlsOcspDbUrl, "tls_ocsp_database_url", "", "OCSP service URL, for database certificates only")
	flag.StringVar(&tlsOcspRequired, "tls_ocsp_required", "yes", "Whether we need OCSP response in order to accept certificate")
	flag.StringVar(&tlsOcspFromCert, "tls_ocsp_from_cert", "prefer", "How should we threat OCSP server described in certificate itself")
	flag.StringVar(&tlsCrlUrl, "tls_crl_url", "", "CRL URL")
	flag.StringVar(&tlsCrlFromCert, "tls_crl_from_cert", "use", "How should we treat CRL URL described in certificate itself")
}

// RegisterTLSClientArgs register CLI args tls_server_sni used by TLS client's connection
func RegisterTLSClientArgs() {
	flag.StringVar(&tlsServerName, "tls_server_sni", "", "Server name used as sni value")
}

// NewTLSConfigFromBaseArgs return new tls config with params passed by cli params
func NewTLSConfigFromBaseArgs() (*tls.Config, error) {
	ocspConfig, err := NewOCSPConfig(tlsOcspUrl, tlsOcspRequired, tlsOcspFromCert)
	if err != nil {
		return nil, err
	}

	ocspVerifier := DefaultOCSPVerifier{Config: *ocspConfig, Client: &DefaultOCSPClient{}}

	crlConfig, err := NewCRLConfig(tlsCrlUrl, tlsCrlFromCert)
	if err != nil {
		return nil, err
	}

	crlVerifier := DefaultCRLVerifier{Config: *crlConfig, Client: DefaultCRLClient{}}

	return NewTLSConfig(tlsServerName, tlsCA, tlsKey, tlsCert, tls.ClientAuthType(tlsAuthType), ocspVerifier, crlVerifier)
}

// NewTLSConfig creates x509 TLS config from provided params, tried to load system CA certificate
func NewTLSConfig(serverName string, caPath, keyPath, crtPath string, authType tls.ClientAuthType, ocspVerifier OCSPVerifier, crlVerifier CRLVerifier) (*tls.Config, error) {
	var roots *x509.CertPool
	var err error
	// use system pool as default
	if roots, err = x509.SystemCertPool(); err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			Errorln("Can't load system ca certificates")
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	// add user's ca if not empty
	if caPath != "" {
		caPem, err := ioutil.ReadFile(caPath)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).Errorln("Can't read root CA certificate")
			return nil, err
		}
		log.Debugln("Adding CA root certificate")
		if ok := roots.AppendCertsFromPEM(caPem); !ok {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkTLSGeneral).Errorln("Can't add CA certificate from PEM")
			return nil, errors.New("can't add CA certificate")
		}
	}
	// use certificate if not empty
	certificates := []tls.Certificate{}
	if crtPath != "" && keyPath != "" {
		cer, err := tls.LoadX509KeyPair(crtPath, keyPath)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, cer)
	}

	verifyPeerCertificate := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		for verifiedChainID := range verifiedChains {
			verifiedChain := verifiedChains[verifiedChainID]

			for verifiedCertID := range verifiedChain {

				cert := verifiedChain[verifiedCertID]

				for i := range cert.CRLDistributionPoints {
					log.Infof("OCSP: certificate contains CRL URI: %s", cert.CRLDistributionPoints[i])
				}
			}

			confirms, err := ocspVerifier.Verify(verifiedChain)
			if err != nil {
				return err
			}

			log.Debugf("OCSP: Got %d confirms about '%s'", confirms, verifiedChain[0].Subject.CommonName)

			confirms, err = crlVerifier.Verify(verifiedChain)
			if err != nil {
				return err
			}

			log.Debugf("CRL: Got %d confirms about '%s'", confirms, verifiedChain[0].Subject.CommonName)
		}

		return nil
	}

	return &tls.Config{
		RootCAs:               roots,
		ClientCAs:             roots,
		Certificates:          certificates,
		ServerName:            serverName,
		ClientAuth:            authType,
		MinVersion:            tls.VersionTLS12,
		CipherSuites:          allowedCipherSuits,
		VerifyPeerCertificate: verifyPeerCertificate,
	}, nil
}

// NewTLSConnectionWrapper returns new TLSConnectionWrapper
func NewTLSConnectionWrapper(clientID []byte, config *tls.Config) (*TLSConnectionWrapper, error) {
	return &TLSConnectionWrapper{config: config, clientID: clientID}, nil
}

// WrapClient wraps client connection into TLS
func (wrapper *TLSConnectionWrapper) WrapClient(ctx context.Context, conn net.Conn) (net.Conn, error) {
	conn.SetDeadline(time.Now().Add(DefaultNetworkTimeout))
	tlsConn := tls.Client(conn, wrapper.config)
	err := tlsConn.Handshake()
	if err != nil {
		conn.SetDeadline(time.Time{})
		return conn, err
	}
	conn.SetDeadline(time.Time{})
	return newSafeCloseConnection(tlsConn), nil
}

// WrapServer wraps server connection into TLS
func (wrapper *TLSConnectionWrapper) WrapServer(ctx context.Context, conn net.Conn) (net.Conn, []byte, error) {
	conn.SetDeadline(time.Now().Add(DefaultNetworkTimeout))
	tlsConn := tls.Server(conn, wrapper.config)
	err := tlsConn.Handshake()
	if err != nil {
		conn.SetDeadline(time.Time{})
		return conn, nil, err
	}
	conn.SetDeadline(time.Time{})
	return newSafeCloseConnection(tlsConn), wrapper.clientID, nil
}

// SetMySQLCompatibleTLSSettings set minimal protocol version to TLSv1.1 and extend list of allowed cipher suits
func SetMySQLCompatibleTLSSettings(config *tls.Config) {
	log.Infoln("Use less secure TLS options to connect to MySQL")
	config.MinVersion = tls.VersionTLS10
	// took from golang sources crypto/tls/cipher_suites.go:71 and order with most secure top, less - bottom,
	// prefer ecdsa to rsa
	config.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,

		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,

		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,

		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	}
}
