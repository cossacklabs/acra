package network

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	tls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func getConnectionPair(address string, listener net.Listener, t testing.TB) (net.Conn, net.Conn) {
	serverConnCh := make(chan net.Conn)
	clientConnCh := make(chan net.Conn)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		serverConnCh <- conn
	}()
	go func() {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		clientConnCh <- conn
	}()
	// wait when client connect to server
	var clientConn, serverConn net.Conn
	for i := 0; i < 2; i++ {
		select {
		case clientConn = <-clientConnCh:
			continue
		case serverConn = <-serverConnCh:
			continue
		case <-time.NewTimer(time.Second / 2).C:
			t.Fatal("Timeout on connection client with server")
		}
	}
	return clientConn, serverConn
}

func getTLSConfigs(t testing.TB) (*tls.Config, *tls.Config) {
	ca := generateTLSCA(t)
	serverTemplate := generateCertificateTemplate(t)
	serverTemplate.Subject.CommonName = "server"
	serverCertificate := createLeafKey(ca, serverTemplate, t)
	// generate tls clientConfig with default parameters but without CA/keys
	serverTLSConfig, err := NewTLSConfig("localhost", "", "", "", tls.RequireAndVerifyClientCert, NewCertVerifierAll())
	if err != nil {
		t.Fatal(err)
	}
	serverTLSConfig.Certificates = []tls.Certificate{serverCertificate}
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	serverTLSConfig.ClientCAs.AddCert(caCert)

	clientTemplate := generateCertificateTemplate(t)
	clientTemplate.Subject.CommonName = "client1"
	clientCertificate := createLeafKey(ca, clientTemplate, t)
	clientTLSConfig, err := NewTLSConfig("localhost", "", "", "", tls.RequireAndVerifyClientCert, NewCertVerifierAll())
	if err != nil {
		t.Fatal(err)
	}
	clientTLSConfig.Certificates = []tls.Certificate{clientCertificate}
	clientTLSConfig.RootCAs.AddCert(caCert)
	return clientTLSConfig, serverTLSConfig
}

func TestTLSWrapperWithCertificateAuthentication(t *testing.T) {
	expectedClientCommonName := []byte("CN=client1,OU=IT,O=Global Security,L=London,C=GB")
	value := sha512.Sum512(expectedClientCommonName)
	expectedClientID := []byte(hex.EncodeToString(value[:]))
	clientConfig, serverConfig := getTLSConfigs(t)
	converter, err := NewDefaultHexIdentifierConverter()
	if err != nil {
		t.Fatal(err)
	}
	extractor, err := NewTLSClientIDExtractor(DistinguishedNameExtractor{}, converter)
	if err != nil {
		t.Fatal(err)
	}
	serverWrapper, err := NewTLSAuthenticationConnectionWrapper(nil, serverConfig, extractor)
	if err != nil {
		t.Fatal(err)
	}
	clientWrapper, err := NewTLSAuthenticationConnectionWrapper(clientConfig, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	testWrapper(clientWrapper, serverWrapper, expectedClientID, wrapperCommunicationIterations, t)
}

func TestTLSWrapperWithStaticClientID(t *testing.T) {
	clientID := []byte(`some client id`)
	clientConfig, serverConfig := getTLSConfigs(t)
	serverWrapper, err := NewTLSConnectionWrapper(clientID, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	clientWrapper, err := NewTLSConnectionWrapper(nil, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	testWrapper(clientWrapper, serverWrapper, clientID, wrapperCommunicationIterations, t)
}

func BenchmarkTLSWrapper(t *testing.B) {
	//  openssl x509 -in client1.crt -subject -noout -nameopt RFC2253 | sed 's/subject=//'
	expectedClientCommonName := []byte("CN=client1,OU=IT,O=Global Security,L=London,ST=London,C=GB")
	expectedClientID := []byte(hex.EncodeToString(expectedClientCommonName))
	clientConfig, serverConfig := getTLSConfigs(t)
	converter, err := NewDefaultHexIdentifierConverter()
	if err != nil {
		t.Fatal(err)
	}
	extractor, err := NewTLSClientIDExtractor(DistinguishedNameExtractor{}, converter)
	if err != nil {
		t.Fatal(err)
	}
	serverWrapper, err := NewTLSAuthenticationConnectionWrapper(nil, serverConfig, extractor)
	if err != nil {
		t.Fatal(err)
	}
	clientWrapper, err := NewTLSAuthenticationConnectionWrapper(clientConfig, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	testWrapper(clientWrapper, serverWrapper, expectedClientID, t.N, t)
}

// isTLS13 return true if connection has version > tls12 constant value in ConnectionState after successful handshake
func isTLS13(conn net.Conn) bool {
	// check with GREATER comparison because golang versions < 1.2 have not constant VersionTLS13
	return UnwrapSafeCloseConnection(conn).(*tls.Conn).ConnectionState().Version > tls.VersionTLS12
}

func TestTLSConfigWeakCipherSuitDeny(t *testing.T) {
	clientConfig, serverConfig := getTLSConfigs(t)
	converter, err := NewDefaultHexIdentifierConverter()
	if err != nil {
		t.Fatal(err)
	}
	extractor, err := NewTLSClientIDExtractor(DistinguishedNameExtractor{}, converter)
	if err != nil {
		t.Fatal(err)
	}
	serverWrapper, err := NewTLSAuthenticationConnectionWrapper(nil, serverConfig, extractor)
	if err != nil {
		t.Fatal(err)
	}
	clientWrapper, err := NewTLSAuthenticationConnectionWrapper(clientConfig, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const host = "localhost"
	listener, err := net.Listen("tcp", host+":0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	clientConn, serverConn := getConnectionPair(fmt.Sprintf("%s:%d", host, port), listener, t)

	wrapErrorCh := make(chan bool)
	// check not allowed cipher suit
	clientWrapper.clientConfig.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256}

	go func() {
		conn, _, err := serverWrapper.WrapServer(context.TODO(), serverConn)
		if err != nil {
			if err.Error() != "tls: no cipher suite supported by both client and server" {
				t.Fatal("Expected error with unsupported ciphersuits")
			}
			wrapErrorCh <- true
			return
		}
		// tls1.3 in golang doesn't support ciphersuites configuration, so just return ok
		if isTLS13(conn) {
			wrapErrorCh <- true
			return
		}
		t.Fatal("expected error")
	}()
	go func() {
		conn, err := clientWrapper.WrapClient(context.TODO(), clientConn)
		if err != nil {
			if err.Error() != "remote error: tls: handshake failure" {
				t.Fatal("Expected with handshake failure")
			}
			wrapErrorCh <- true
			return
		}
		// tls1.3 in golang doesn't support ciphersuites configuration, so just return ok
		if isTLS13(conn) {
			wrapErrorCh <- true
			return
		}
		t.Fatal("expected error")
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-wrapErrorCh:
			continue
		case <-time.NewTimer(time.Second / 2).C:
			t.Fatal("Timeout on wrap with incorrect cipher suits")
		}
	}
	if err = clientConn.Close(); err != nil {
		t.Fatal(err)
	}
	if err = serverConn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTLSConfigWeakVersion(t *testing.T) {
	clientConfig, serverConfig := getTLSConfigs(t)
	clientID := []byte(`some client`)
	serverWrapper, err := NewTLSConnectionWrapper(clientID, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	clientWrapper, err := NewTLSConnectionWrapper(nil, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	clientWrapper.clientConfig.MinVersion = tls.VersionSSL30
	clientWrapper.clientConfig.MaxVersion = tls.VersionTLS11

	matchedServerSideError := func(err error) bool {
		expectedMessages := []string{
			// go < 1.12
			"tls: client offered an unsupported, maximum protocol version of",
			// go >= 1.12
			"tls: client offered only unsupported versions"}
		found := false
		for _, msg := range expectedMessages {
			if strings.HasPrefix(err.Error(), msg) {
				found = true
			}
		}
		return found
	}

	matchedClientSideError := func(err error) bool {
		return err.Error() == "remote error: tls: protocol version not supported"
	}

	matchedServerSide := false
	matchedClientSide := false
	mutex := sync.Mutex{}
	// we expects 2 errors, one from client side and from server side related with protocol version is unsupported
	onError := func(err error, t testing.TB) {
		mutex.Lock()
		defer mutex.Unlock()
		if matchedServerSide && matchedClientSide {
			return
		}
		if matchedClientSideError(err) {
			matchedClientSide = true
		}
		if matchedServerSideError(err) {
			matchedServerSide = true
		}
		if !(matchedServerSide || matchedClientSide) {
			t.Fatalf("Unexpected error %s\n", err)
		}
	}
	testWrapperWithError(clientWrapper, serverWrapper, clientID, 1, onError, t)
}
func TestTLSCertificateAuthenticationByCommonName(t *testing.T) {
	clientConfig, serverConfig := getTLSConfigs(t)
	//  openssl x509 -in client1.crt -subject -noout -nameopt RFC2253 | sed 's/subject=//'
	expectedClientCommonName := []byte("CN=client1,OU=IT,O=Global Security,L=London,C=GB")
	value := sha512.Sum512(expectedClientCommonName)
	expectedClientID := []byte(hex.EncodeToString(value[:]))
	serverHost := "localhost"
	clientConfig.ServerName = serverHost

	converter, err := NewDefaultHexIdentifierConverter()
	if err != nil {
		t.Fatal(err)
	}
	extractor, err := NewTLSClientIDExtractor(DistinguishedNameExtractor{}, converter)
	if err != nil {
		t.Fatal(err)
	}
	serverWrapper, err := NewTLSAuthenticationConnectionWrapper(nil, serverConfig, extractor)
	if err != nil {
		t.Fatal(err)
	}
	clientWrapper, err := NewTLSAuthenticationConnectionWrapper(clientConfig, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	testWrapper(clientWrapper, serverWrapper, expectedClientID, wrapperCommunicationIterations, t)
}

func TestTLSCertificateAuthenticationBySerialNumber(t *testing.T) {
	clientConfig, serverConfig := getTLSConfigs(t)
	converter, err := NewDefaultHexIdentifierConverter()
	if err != nil {
		t.Fatal(err)
	}
	extractor, err := NewTLSClientIDExtractor(SerialNumberExtractor{}, converter)
	if err != nil {
		t.Fatal(err)
	}
	serverWrapper, err := NewTLSAuthenticationConnectionWrapper(nil, serverConfig, extractor)
	if err != nil {
		t.Fatal(err)
	}
	clientWrapper, err := NewTLSAuthenticationConnectionWrapper(clientConfig, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	clientCertificate, err := x509.ParseCertificate(clientConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	value := sha512.Sum512(clientCertificate.SerialNumber.Bytes())
	expectedClientID := []byte(hex.EncodeToString(value[:]))
	testWrapper(clientWrapper, serverWrapper, expectedClientID, wrapperCommunicationIterations, t)
}

func TestEmptyCertificateChain(t *testing.T) {
	clientConfig, serverConfig := getTLSConfigs(t)
	converter, err := NewDefaultHexIdentifierConverter()
	if err != nil {
		t.Fatal(err)
	}
	extractor, err := NewTLSClientIDExtractor(DistinguishedNameExtractor{}, converter)
	if err != nil {
		t.Fatal(err)
	}
	serverWrapper, err := NewTLSAuthenticationConnectionWrapper(nil, serverConfig, extractor)
	if err != nil {
		t.Fatal(err)
	}
	// remove client's CA to not pass verification to check that empty VerifiedChain not pass
	serverWrapper.serverConfig.ClientCAs = x509.NewCertPool()
	serverWrapper.serverConfig.ClientAuth = tls.RequireAnyClientCert
	clientWrapper, err := NewTLSAuthenticationConnectionWrapper(clientConfig, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := x509.ParseCertificate(clientConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	expectedClientID, err := serverWrapper.getClientIDFromCertificate(clientCertificate)
	if err != nil {
		t.Fatal(err)
	}
	// expect that first error will be ErrNoPeerCertificate
	tested := false
	mutex := sync.Mutex{}
	onError := func(err error, t testing.TB) {
		mutex.Lock()
		defer mutex.Unlock()
		if tested {
			return
		}
		if err == ErrNoPeerCertificate {
			tested = true
			return
		}
		t.Fatalf("Expected error ErrNoPeerCertificate, took %s\n", err)
	}
	testWrapperWithError(clientWrapper, serverWrapper, expectedClientID, 1, onError, t)
}

func TestClientsCertificateDenyOnValidation(t *testing.T) {
	clientConfig, serverConfig := getTLSConfigs(t)
	ca := generateTLSCA(t)
	clientCertificateTemplate := generateCertificateTemplate(t)
	clientCertificateTemplate.IsCA = true
	clientCertificateTemplate.Subject.CommonName = "client"
	clientCertificate := createLeafKey(ca, clientCertificateTemplate, t)
	clientConfig.Certificates = []tls.Certificate{clientCertificate}
	caCrt, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	serverConfig.ClientCAs.AddCert(caCrt)

	clientWrapper, err := NewTLSAuthenticationConnectionWrapper(clientConfig, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	converter, err := NewDefaultHexIdentifierConverter()
	if err != nil {
		t.Fatal(err)
	}
	extractor, err := NewTLSClientIDExtractor(DistinguishedNameExtractor{}, converter)
	if err != nil {
		t.Fatal(err)
	}
	serverWrapper, err := NewTLSAuthenticationConnectionWrapper(nil, serverConfig, extractor)
	if err != nil {
		t.Fatal(err)
	}
	clientCrt, err := x509.ParseCertificate(clientCertificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	expectedClientID, err := serverWrapper.getClientIDFromCertificate(clientCrt)
	if err != nil {
		t.Fatal(err)
	}
	// expect that first error will be ErrCACertificateUsed
	tested := false
	mutex := sync.Mutex{}
	onError := func(err error, t testing.TB) {
		mutex.Lock()
		defer mutex.Unlock()
		if tested {
			return
		}
		if err == ErrCACertificateUsed {
			tested = true
			return
		}
		t.Fatalf("Expected error ErrCACertificateUsed, took %s\n", err)
	}
	testWrapperWithError(clientWrapper, serverWrapper, expectedClientID, 1, onError, t)
}

type testExtractor struct{ err error }

func (e testExtractor) GetCertificateIdentifier(certificate *x509.Certificate) ([]byte, error) {
	return nil, e.err
}

func TestClientsCertificateDenyOnClientIDExtraction(t *testing.T) {
	clientConfig, serverConfig := getTLSConfigs(t)
	clientWrapper, err := NewTLSAuthenticationConnectionWrapper(clientConfig, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	converter, err := NewDefaultHexIdentifierConverter()
	if err != nil {
		t.Fatal(err)
	}
	extractor, err := NewTLSClientIDExtractor(DistinguishedNameExtractor{}, converter)
	if err != nil {
		t.Fatal(err)
	}
	serverWrapper, err := NewTLSAuthenticationConnectionWrapper(nil, serverConfig, extractor)
	if err != nil {
		t.Fatal(err)
	}

	clientCrt, err := x509.ParseCertificate(clientConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	expectedClientID, err := serverWrapper.getClientIDFromCertificate(clientCrt)
	if err != nil {
		t.Fatal(err)
	}

	// override extractor which will always return err
	expectedErr := errors.New("test error")
	testExtractor, err := NewTLSClientIDExtractor(testExtractor{err: expectedErr}, converter)
	if err != nil {
		t.Fatal(err)
	}
	serverWrapper.clientIDExtractor = testExtractor

	tested := false
	mutex := sync.Mutex{}
	onError := func(err error, t testing.TB) {
		mutex.Lock()
		defer mutex.Unlock()
		if tested {
			return
		}
		if err == expectedErr {
			tested = true
			return
		}
		t.Fatalf("Expected error expectedErr, took %s\n", err)
	}
	testWrapperWithError(clientWrapper, serverWrapper, expectedClientID, 1, onError, t)
}

type testConvertor struct{ err error }

func (t testConvertor) Convert(identifier []byte) ([]byte, error) {
	return nil, t.err
}

func TestClientsCertificateDenyOnClientIDConvertation(t *testing.T) {
	clientConfig, serverConfig := getTLSConfigs(t)
	clientWrapper, err := NewTLSAuthenticationConnectionWrapper(clientConfig, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	converter, err := NewDefaultHexIdentifierConverter()
	if err != nil {
		t.Fatal(err)
	}
	extractor, err := NewTLSClientIDExtractor(DistinguishedNameExtractor{}, converter)
	if err != nil {
		t.Fatal(err)
	}
	serverWrapper, err := NewTLSAuthenticationConnectionWrapper(nil, serverConfig, extractor)
	if err != nil {
		t.Fatal(err)
	}

	clientCrt, err := x509.ParseCertificate(clientConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	expectedClientID, err := serverWrapper.getClientIDFromCertificate(clientCrt)
	if err != nil {
		t.Fatal(err)
	}

	// override convertor which will always return err
	expectedErr := errors.New("test error")
	testExtractor, err := NewTLSClientIDExtractor(DistinguishedNameExtractor{}, testConvertor{err: expectedErr})
	if err != nil {
		t.Fatal(err)
	}
	serverWrapper.clientIDExtractor = testExtractor

	tested := false
	mutex := sync.Mutex{}
	onError := func(err error, t testing.TB) {
		mutex.Lock()
		defer mutex.Unlock()
		if tested {
			return
		}
		if err == expectedErr {
			tested = true
			return
		}
		t.Fatalf("Expected error expectedErr, took %s\n", err)
	}
	testWrapperWithError(clientWrapper, serverWrapper, expectedClientID, 1, onError, t)
}

func generateTLSCA(t testing.TB) tls.Certificate {
	// set up our CA certificate
	caTemplate := generateCertificateTemplate(t)
	caTemplate.IsCA = true
	caTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	return generateTLSCAFromTemplate(caTemplate, t)
}

func generateTLSCAFromTemplate(caTemplate *x509.Certificate, t testing.TB) tls.Certificate {
	// create our private and public key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privateKeyPEM := new(bytes.Buffer)
	pem.Encode(privateKeyPEM, privateBlock)

	// create the CA
	certificateBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	certificatePEM := new(bytes.Buffer)
	certificateBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateBytes,
	}
	pem.Encode(certificatePEM, certificateBlock)

	tlsCertificate, err := tls.X509KeyPair(certificatePEM.Bytes(), privateKeyPEM.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return tlsCertificate
}
func createLeafKey(caCert tls.Certificate, templateCertificate *x509.Certificate, t testing.TB) tls.Certificate {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caCrt, err := x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	certificateBytes, err := x509.CreateCertificate(rand.Reader, templateCertificate, caCrt, &privateKey.PublicKey, caCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	certificatePEMBytes := new(bytes.Buffer)
	certificateBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateBytes,
	}
	pem.Encode(certificatePEMBytes, certificateBlock)

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privateKeyPEMBytes := new(bytes.Buffer)
	pem.Encode(privateKeyPEMBytes, privateKeyBlock)

	tlsCertificate, err := tls.X509KeyPair(certificatePEMBytes.Bytes(), privateKeyPEMBytes.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return tlsCertificate
}
func generateCertificateTemplate(t testing.TB) *x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{"GB"},
			Locality:           []string{"London"},
			Organization:       []string{"Global Security"},
			OrganizationalUnit: []string{"IT"},
			CommonName:         "CA certificate",
		},
		DNSNames:              []string{"localhost"},
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment,
		BasicConstraintsValid: true,
	}
}

func TestTLSGRPCClientIDExtractorSuccess(t *testing.T){
	clientCert := generateCertificateTemplate(t)
	testClientID := "client1"
	clientCert.Subject.CommonName = testClientID
	authInfo := credentials.TLSInfo{State: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{clientCert}}}}
	ctx := context.Background()
	ctx = peer.NewContext(ctx, &peer.Peer{AuthInfo: authInfo})
	idConverter, err := NewDefaultHexIdentifierConverter()
	if err != nil {
		t.Fatal(err)
	}
	tlsClientIDExtractor, err := NewTLSClientIDExtractor(DistinguishedNameExtractor{}, idConverter)
	if err != nil {
		t.Fatal(err)
	}
	expectedClientID, err := tlsClientIDExtractor.ExtractClientID(clientCert)
	if err != nil {
		t.Fatal(err)
	}
	newTLSClientIDExtractor, err := NewTLSGRPCClientIDExtractor(tlsClientIDExtractor)
	if err != nil {
		t.Fatal(err)
	}
	resultClientID, err := newTLSClientIDExtractor.ExtractClientID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, resultClientID, expectedClientID)
}

func TestGRPCClientIDExtractorInvalidContext(t *testing.T){
	extractor, err := NewTLSGRPCClientIDExtractor(nil)
	if err != nil {
		t.Fatal(err)
	}
	testRPCClientIDExtractorInvalidContext(extractor, t)
}

func TestTLSGRPCClientIDExtractorIncorrectAuthInfo(t *testing.T){
	ctx := context.Background()
	ctx = peer.NewContext(ctx, &peer.Peer{AuthInfo: SecureSessionInfo{}})
	tlsClientIDExtractor, err := NewTLSClientIDExtractor(DistinguishedNameExtractor{}, &hexIdentifierConverter{})
	if err != nil {
		t.Fatal(err)
	}
	extractor, err := NewTLSGRPCClientIDExtractor(tlsClientIDExtractor)
	if err != nil {
		t.Fatal(err)
	}
	testTLSGRPCClientIDExtractorIncorrectAuthInfo(extractor, t)
}