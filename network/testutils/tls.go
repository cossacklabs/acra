package testutils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

// GenerateTLSCA return CA certificate template for test purposes
func GenerateTLSCA() (tls.Certificate, error) {
	// set up our CA certificate
	caTemplate, err := GenerateCertificateTemplate()
	if err != nil {
		return tls.Certificate{}, nil
	}
	caTemplate.IsCA = true
	caTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	template, err := GenerateTLSCAFromTemplate(caTemplate)
	if err != nil {
		return tls.Certificate{}, err
	}
	return template, nil
}

// GenerateTLSCAFromTemplate return CA certificate for test purposes
func GenerateTLSCAFromTemplate(caTemplate *x509.Certificate) (tls.Certificate, error) {
	// create our private and public key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil
	}
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, nil
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
		return tls.Certificate{}, nil
	}

	certificatePEM := new(bytes.Buffer)
	certificateBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateBytes,
	}
	pem.Encode(certificatePEM, certificateBlock)

	tlsCertificate, err := tls.X509KeyPair(certificatePEM.Bytes(), privateKeyPEM.Bytes())
	if err != nil {
		return tls.Certificate{}, nil
	}
	return tlsCertificate, nil
}

// CreateLeafKey return leaf certificate for test purposes
func CreateLeafKey(caCert tls.Certificate, templateCertificate *x509.Certificate) (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	caCrt, err := x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	certificateBytes, err := x509.CreateCertificate(rand.Reader, templateCertificate, caCrt, &privateKey.PublicKey, caCert.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certificatePEMBytes := new(bytes.Buffer)
	certificateBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateBytes,
	}
	pem.Encode(certificatePEMBytes, certificateBlock)

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privateKeyPEMBytes := new(bytes.Buffer)
	pem.Encode(privateKeyPEMBytes, privateKeyBlock)

	tlsCertificate, err := tls.X509KeyPair(certificatePEMBytes.Bytes(), privateKeyPEMBytes.Bytes())
	if err != nil {
		return tls.Certificate{}, err
	}
	return tlsCertificate, nil
}

// GenerateCertificateTemplate return certificate template for test purposes
func GenerateCertificateTemplate() (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
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
	}, nil
}

// ConfigGenerator used as generator to allow pass wrapper for NewTLSConfig and avoid cyclic import from network package
type ConfigGenerator func() *tls.Config

// GetTestTLSConfigs return client and server TLS configs for test purposes
func GetTestTLSConfigs(clientConfigGenerator, serverConfigGenerator ConfigGenerator) (*tls.Config, *tls.Config, error) {
	ca, err := GenerateTLSCA()
	if err != nil {
		return nil, nil, err
	}
	serverTemplate, err := GenerateCertificateTemplate()
	if err != nil {
		return nil, nil, err
	}
	serverTemplate.Subject.CommonName = "server"
	serverCertificate, err := CreateLeafKey(ca, serverTemplate)
	if err != nil {
		return nil, nil, err
	}
	// generate tls clientConfig with default parameters but without CA/keys
	serverTLSConfig := serverConfigGenerator()

	serverTLSConfig.Certificates = []tls.Certificate{serverCertificate}
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	serverTLSConfig.ClientCAs.AddCert(caCert)

	clientTemplate, err := GenerateCertificateTemplate()
	if err != nil {
		return nil, nil, err
	}
	clientTemplate.Subject.CommonName = "client1"
	clientCertificate, err := CreateLeafKey(ca, clientTemplate)
	if err != nil {
		return nil, nil, err
	}
	clientTLSConfig := clientConfigGenerator()
	clientTLSConfig.Certificates = []tls.Certificate{clientCertificate}
	clientTLSConfig.RootCAs.AddCert(caCert)
	return clientTLSConfig, serverTLSConfig, nil
}
