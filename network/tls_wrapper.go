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
	"io/ioutil"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/credentials"

	"github.com/cossacklabs/acra/logging"
)

// allowedCipherSuits that set in default tls clientConfig
var allowedCipherSuits = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}

const tlsAuthNotSet = -1

// TLSConnectionWrapper for wrapping connection into TLS encryption
type TLSConnectionWrapper struct {
	credentials.TransportCredentials
	clientConfig               *tls.Config
	serverConfig               *tls.Config
	clientID                   []byte
	clientIDExtractor          TLSClientIDExtractor
	useClientIDFromCertificate bool
	onServerHandshakeCallbacks []OnServerHandshakeCallback
}

// ErrEmptyTLSConfig if not TLS clientConfig found
var ErrEmptyTLSConfig = errors.New("empty TLS clientConfig")

var (
	tlsCA         string
	tlsKey        string
	tlsCert       string
	tlsAuthType   int
	tlsServerName string
)

// CLIParamNameConstructorFunc func compiles final parameter name for specified service name
type CLIParamNameConstructorFunc func(serviceName, parameterName, groupName string) string

// ClientNameConstructorFunc returns CLIParamNameConstructorFunc with "_client_" suffix before parameter name
func ClientNameConstructorFunc() CLIParamNameConstructorFunc {
	return func(serviceName, parameterName, groupName string) string {
		// serviceName = "vault
		// parameterName = "key"
		// result = "vault_tls_client_key
		if groupName != "" {
			groupName = groupName + "_"
		}
		if serviceName == "" {
			return "tls_" + groupName + "client_" + parameterName
		}
		return serviceName + "_tls_" + groupName + "client_" + parameterName
	}
}

// DatabaseNameConstructorFunc returns CLIParamNameConstructorFunc with "_database_" suffix before parameter name
func DatabaseNameConstructorFunc() CLIParamNameConstructorFunc {
	return func(serviceName, parameterName, groupName string) string {
		// serviceName = "vault
		// parameterName = "key"
		// groupName = "ocsp"
		// result = "vault_tls_ocsp_database_key
		if groupName != "" {
			groupName = groupName + "_"
		}
		if serviceName == "" {
			return "tls_" + groupName + "database_" + parameterName
		}
		return serviceName + "_tls_" + groupName + "database_" + parameterName
	}
}

// RegisterTLSBaseArgs register CLI args tls_ca|tls_key|tls_cert|tls_auth which allow to get tls.Config by NewTLSConfigFromBaseArgs function
func RegisterTLSBaseArgs(flags *flag.FlagSet) {
	flags.StringVar(&tlsCA, "tls_ca", "", "Path to root certificate which will be used with system root certificates to validate peer's certificate")
	flags.StringVar(&tlsKey, "tls_key", "", "Path to private key that will be used for TLS connections")
	flags.StringVar(&tlsCert, "tls_cert", "", "Path to certificate")
	flags.IntVar(&tlsAuthType, "tls_auth", int(tls.RequireAndVerifyClientCert), "Set authentication mode that will be used in TLS connection. Values in range 0-4 that set auth type (https://golang.org/pkg/crypto/tls/#ClientAuthType). Default is tls.RequireAndVerifyClientCert")
	RegisterCertVerifierArgs(flags)
}

// RegisterTLSArgsForService register CLI args tls_ca|tls_key|tls_cert|tls_auth and flags for certificate verifier
// which allow to get tls.Config by NewTLSConfigByName function
func RegisterTLSArgsForService(flags *flag.FlagSet, isClient bool, name string, namerFunc CLIParamNameConstructorFunc) {
	flags.String(namerFunc(name, "ca", ""), "", "Path to root certificate which will be used with system root certificates to validate peer's certificate. Uses --tls_ca value if not specified.")
	flags.String(namerFunc(name, "key", ""), "", "Path to private key that will be used for TLS connections. Uses --tls_key value if not specified.")
	flags.String(namerFunc(name, "cert", ""), "", "Path to certificate. Uses --tls_cert value if not specified.")
	flags.Int(namerFunc(name, "auth", ""), int(tlsAuthNotSet), "Set authentication mode that will be used in TLS connection. Values in range 0-4 that set auth type (https://golang.org/pkg/crypto/tls/#ClientAuthType). Default is -1 which means NotSpecified and will be used value from tls_auth.")
	// if Acra's component is client for TLS handshake, it can specify expected SNI from the server's side
	// otherwise skip it for server's role of Acra
	if isClient {
		flags.String(namerFunc(name, "sni", ""), "", "Expected Server Name (SNI) from the service's side.")
	}
	RegisterCertVerifierArgsForService(flags, name, namerFunc)
}

type ParamsExtractor interface {
	GetString(param, generalParam string) string
	GetBool(param, generalParam string) bool
	GetInt(param, generalParam string) int
}

// NewTLSConfigByName returns config related to flags registered via RegisterTLSArgsForService. `host` will be used as
// ServerName in tls.Config for connection as client to verify server's certificate.
// If <name>_tls_sni flag specified, then will be used SNI value.
func NewTLSConfigByName(extractor ParamsExtractor, name, host string, namerFunc CLIParamNameConstructorFunc) (*tls.Config, error) {
	var (
		ca   = extractor.GetString(namerFunc(name, "ca", ""), "tls_ca")
		sni  = extractor.GetString(namerFunc(name, "sni", ""), "")
		cert = extractor.GetString(namerFunc(name, "cert", ""), "tls_cert")
		key  = extractor.GetString(namerFunc(name, "key", ""), "tls_key")
	)

	v := extractor.GetInt(namerFunc(name, "auth", ""), "")
	if v == tlsAuthNotSet {
		v = tlsAuthType
	}
	auth := tls.ClientAuthType(v)

	ocspConfig, err := NewOCSPConfigByName(extractor, name, namerFunc)
	if err != nil {
		return nil, err
	}

	crlConfig, err := NewCRLConfigByName(extractor, name, namerFunc)
	if err != nil {
		return nil, err
	}

	verifier, err := NewCertVerifierFromConfigs(ocspConfig, crlConfig)
	if err != nil {
		return nil, err
	}
	return NewTLSConfig(SNIOrHostname(sni, host), ca, key, cert, auth, verifier)
}

// NewTLSConfigFromBaseArgs return new tls clientConfig with params passed by cli params
func NewTLSConfigFromBaseArgs() (*tls.Config, error) {
	certVerifier, err := NewCertVerifier()
	if err != nil {
		return nil, err
	}

	return NewTLSConfig(tlsServerName, tlsCA, tlsKey, tlsCert, tls.ClientAuthType(tlsAuthType), certVerifier)
}

// NewTLSConfig creates x509 TLS clientConfig from provided params, tried to load system CA certificate
func NewTLSConfig(serverName string, caPath, keyPath, crtPath string, authType tls.ClientAuthType, certVerifier CertVerifier) (*tls.Config, error) {
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

	// default do nothing
	verifyPeerCertificate := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error { return nil }
	if certVerifier != nil {
		verifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			err := certVerifier.Verify(rawCerts, verifiedChains)

			log.WithError(err).WithField("valid", err == nil).Debugln("verifyPeerCertificate")

			return err
		}
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

// wrappedTLSAuthInfo wraps credentials.TLSInfo and store connection for future access to retrieve connection metadata
type wrappedTLSAuthInfo struct {
	credentials.TLSInfo
	conn net.Conn
}

// Connection return wrapped connection
func (authInfo *wrappedTLSAuthInfo) Connection() net.Conn {
	return authInfo.conn
}

// NewTLSConnectionWrapper returns new TLSConnectionWrapper
func NewTLSConnectionWrapper(clientID []byte, config *tls.Config) (*TLSConnectionWrapper, error) {
	return &TLSConnectionWrapper{clientConfig: config, serverConfig: config, clientID: clientID, TransportCredentials: credentials.NewTLS(config)}, nil
}

// ErrInvalidTLSConfiguration used for invalid configurations for TLS connections
var ErrInvalidTLSConfiguration = errors.New("invalid auth_type for TLS config")

// NewTLSAuthenticationConnectionWrapper returns new TLSConnectionWrapper which use separate TLS configs for each side. Client's identifier will be fetched
// with idExtractor and converter with idConverter
func NewTLSAuthenticationConnectionWrapper(useClientIDFromCertificate bool, clientConfig, serverConfig *tls.Config, extractor TLSClientIDExtractor) (*TLSConnectionWrapper, error) {
	// we can't extract clientID metadata without client's certificates
	if useClientIDFromCertificate && (serverConfig == nil || serverConfig.ClientAuth == tls.NoClientCert) {
		return nil, ErrInvalidTLSConfiguration
	}
	if serverConfig != nil && !strSliceContains(serverConfig.NextProtos, http2NextProtoTLS) {
		tlsCopy := serverConfig.Clone()
		tlsCopy.NextProtos = append(tlsCopy.NextProtos, http2NextProtoTLS)
		serverConfig = tlsCopy
	}
	return &TLSConnectionWrapper{clientConfig: clientConfig, serverConfig: serverConfig, clientIDExtractor: extractor,
		useClientIDFromCertificate: useClientIDFromCertificate, TransportCredentials: credentials.NewTLS(serverConfig)}, nil
}

// strSliceContains return true if stringSlice contains string value
func strSliceContains(stringSlice []string, value string) bool {
	for _, v := range stringSlice {
		if v == value {
			return true
		}
	}
	return false
}

// NextProtoTLS is the NPN/ALPN protocol negotiated during
// HTTP/2's TLS setup.
const http2NextProtoTLS = "h2"

// NewTLSAuthenticationHTTP2ConnectionWrapper returns new TLSConnectionWrapper which use separate TLS configs for each side. Client's identifier will be fetched
// with idExtractor and converter with idConverter. Additionally extends serverConfig with NextProtos = []string{"h2"} to support HTTP2
func NewTLSAuthenticationHTTP2ConnectionWrapper(useClientIDFromCertificate bool, clientConfig, serverConfig *tls.Config, extractor TLSClientIDExtractor) (*TLSConnectionWrapper, error) {
	// we can't extract clientID metadata without client's certificates
	if useClientIDFromCertificate && (serverConfig == nil || serverConfig.ClientAuth == tls.NoClientCert) {
		return nil, ErrInvalidTLSConfiguration
	}
	if !strSliceContains(serverConfig.NextProtos, http2NextProtoTLS) {
		tlsCopy := serverConfig.Clone()
		tlsCopy.NextProtos = append(tlsCopy.NextProtos, http2NextProtoTLS)
		serverConfig = tlsCopy
	}

	return &TLSConnectionWrapper{clientConfig: clientConfig, serverConfig: serverConfig, clientIDExtractor: extractor,
		useClientIDFromCertificate: useClientIDFromCertificate, TransportCredentials: credentials.NewTLS(serverConfig)}, nil
}

// AddOnServerHandshakeCallback register callback that will be called on ServerHandshake call from grpc connection handler
func (wrapper *TLSConnectionWrapper) AddOnServerHandshakeCallback(callback OnServerHandshakeCallback) {
	wrapper.onServerHandshakeCallbacks = append(wrapper.onServerHandshakeCallbacks, callback)
}

// ServerHandshake wraps connection with grpc's implementation of ServerHandshake and call all registered OnServerHandshakeCallbacks and return extended AuthInfo with wrapped connection
// with clientID information
func (wrapper *TLSConnectionWrapper) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	newConn, authInfo, err := wrapper.TransportCredentials.ServerHandshake(conn)
	if err != nil {
		return newConn, authInfo, err
	}
	wrappedConn := newConn
	for _, callback := range wrapper.onServerHandshakeCallbacks {
		wrappedConn, err = callback.OnServerHandshake(wrappedConn)
		if err != nil {
			return newConn, authInfo, err
		}
	}
	tlsAuthInfo, ok := authInfo.(credentials.TLSInfo)
	if !ok {
		return wrappedConn, authInfo, ErrIncorrectGRPCConnectionAuthInfo
	}
	if len(tlsAuthInfo.State.VerifiedChains) == 0 || len(tlsAuthInfo.State.VerifiedChains[0]) == 0 {
		return wrappedConn, authInfo, ErrNoPeerCertificate
	}
	certificate := tlsAuthInfo.State.VerifiedChains[0][0]
	clientID, err := wrapper.clientIDExtractor.ExtractClientID(certificate)
	if err != nil {
		return wrappedConn, authInfo, err
	}
	clientIDConn := newClientIDConnection(wrappedConn, clientID)
	return clientIDConn, &wrappedTLSAuthInfo{TLSInfo: tlsAuthInfo, conn: clientIDConn}, nil
}

// WrapClient wraps client connection into TLS
func (wrapper *TLSConnectionWrapper) WrapClient(ctx context.Context, conn net.Conn) (net.Conn, error) {
	conn.SetDeadline(time.Now().Add(DefaultNetworkTimeout))
	tlsConn := tls.Client(conn, wrapper.clientConfig)
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
	tlsConn := tls.Server(conn, wrapper.serverConfig)
	err := tlsConn.Handshake()
	if err != nil {
		conn.SetDeadline(time.Time{})
		return conn, nil, err
	}
	conn.SetDeadline(time.Time{})
	var clientID []byte
	// extract clientID from certificate only if auth_type require any certificate
	if wrapper.useClientIDFromCertificate {
		clientID, err = GetClientIDFromTLSConn(tlsConn, wrapper.clientIDExtractor)
		if err != nil {
			return conn, nil, err
		}
		return tlsConn, clientID, nil
	}
	return tlsConn, wrapper.clientID, nil
}

// OnConnection callback that wraps connection with tls encryption and return ClientIDConnection
func (wrapper *TLSConnectionWrapper) OnConnection(conn net.Conn) (net.Conn, error) {
	log.Debugln("Wrap connection with TLS")
	wrappedConn, _, err := wrapper.WrapServer(context.Background(), conn)
	if err != nil {
		return conn, err
	}
	return wrappedConn, nil
}

// getClientIDFromCertificate validate certificate and extract clientID from certificate
func getClientIDFromCertificate(certificate *x509.Certificate, extractor TLSClientIDExtractor) ([]byte, error) {
	if err := ValidateClientsAuthenticationCertificate(certificate); err != nil {
		return nil, err
	}
	clientID, err := extractor.ExtractClientID(certificate)
	if err != nil {
		return nil, err
	}
	log.WithField("clientID", string(clientID)).Debugln("ClientID from certificate")
	return clientID, nil
}

// GetClientIDFromTLSConn extracts clientID from tls.Conn metadata using extractor
func GetClientIDFromTLSConn(conn *tls.Conn, extractor TLSClientIDExtractor) ([]byte, error) {
	connectionInfo := conn.ConnectionState()
	if len(connectionInfo.VerifiedChains) == 0 || len(connectionInfo.VerifiedChains[0]) == 0 {
		return nil, ErrNoPeerCertificate
	}
	certificate := connectionInfo.VerifiedChains[0][0]
	return getClientIDFromCertificate(certificate, extractor)
}
