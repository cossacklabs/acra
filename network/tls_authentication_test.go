package network

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

// getWorkingDirectory expects that tests started from root of source code and accessible tests/ssl folder, otherwise call t.Fatal otherwise
func getWorkingDirectory(t *testing.T) string {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	sslTestFolder := filepath.Join(workingDirectory, "tests/ssl")
	info, err := os.Lstat(sslTestFolder)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("'%s' is not directory as expected\n", sslTestFolder)
	}
	return workingDirectory
}

func getAcraWriterTestx509Certificate(t *testing.T) *x509.Certificate {
	certPath := filepath.Join(getWorkingDirectory(t), "tests/ssl/acra-writer/acra-writer.crt")
	certificateData, err := ioutil.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificateData)
	if block == nil {
		t.Fatal("Empty block from PEM certificate")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestSerialNumberExtractor_GetCertificateIdentifier(t *testing.T) {
	certificate := getAcraWriterTestx509Certificate(t)
	serialNumber := certificate.SerialNumber.Bytes()
	identifier, err := SerialNumberExtractor{}.GetCertificateIdentifier(certificate)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(serialNumber, identifier) {
		t.Fatal("SerialNumberExtractor return something else than serial number as identifier")
	}
}
func TestCommonNameExtractor_GetCertificateIdentifier(t *testing.T) {
	certificate := getAcraWriterTestx509Certificate(t)
	commonName := []byte(certificate.Subject.String())
	identifier, err := CommonNameExtractor{}.GetCertificateIdentifier(certificate)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(commonName, identifier) {
		t.Fatal("CommonNameExtractor return something else than Subject as DN as identifier")
	}
}

func TestValidateClientsAuthenticationCertificate(t *testing.T) {
	if err := ValidateClientsAuthenticationCertificate(nil); err != ErrNoPeerCertificate {
		t.Fatal("Not denied empty certificate")
	}

	if err := ValidateClientsAuthenticationCertificate(&x509.Certificate{IsCA: true}); err != ErrCACertificateUsed {
		t.Fatal("Not denied certificate for CA purposes")
	}
	// test without any key usage
	if err := ValidateClientsAuthenticationCertificate(&x509.Certificate{}); err != ErrMissedAuthenticationKeyUsage {
		t.Fatal("Not denied certificate with acceptable KeyUsage/ExtKeyUsage")
	}

	// all purposes except digital signature
	invalidKeyUsage := 0xFFFFFFFF ^ x509.KeyUsageDigitalSignature
	// all purposes except ClientAuth
	invalidExtKeyUsage := []x509.ExtKeyUsage{
		x509.ExtKeyUsageAny,
		x509.ExtKeyUsageServerAuth,
		//x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageCodeSigning,
		x509.ExtKeyUsageEmailProtection,
		x509.ExtKeyUsageIPSECEndSystem,
		x509.ExtKeyUsageIPSECTunnel,
		x509.ExtKeyUsageIPSECUser,
		x509.ExtKeyUsageTimeStamping,
		x509.ExtKeyUsageOCSPSigning,
		x509.ExtKeyUsageMicrosoftServerGatedCrypto,
		x509.ExtKeyUsageNetscapeServerGatedCrypto,
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
		x509.ExtKeyUsageMicrosoftKernelCodeSigning,
	}
	// test with not empty KeyUsage and ExtKeyUsage but without expected values
	certificate := &x509.Certificate{KeyUsage: invalidKeyUsage, ExtKeyUsage: invalidExtKeyUsage}
	if err := ValidateClientsAuthenticationCertificate(certificate); err != ErrMissedAuthenticationKeyUsage {
		t.Fatal("Not denied certificate with acceptable KeyUsage/ExtKeyUsage")
	}

	// test only with correct KeyUsage
	certificate = &x509.Certificate{
		KeyUsage:    invalidKeyUsage | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: invalidExtKeyUsage}
	if err := ValidateClientsAuthenticationCertificate(certificate); err != nil {
		t.Fatalf("Took %s error instead nil\n", err)
	}

	// test only with correct ExtKeyUsage
	certificate = &x509.Certificate{
		KeyUsage:    invalidKeyUsage,
		ExtKeyUsage: append(invalidExtKeyUsage, x509.ExtKeyUsageClientAuth)}
	if err := ValidateClientsAuthenticationCertificate(certificate); err != nil {
		t.Fatalf("Took %s error instead nil\n", err)
	}

	// test only with correct ExtKeyUsage
	certificate = &x509.Certificate{
		KeyUsage:    invalidKeyUsage | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: append(invalidExtKeyUsage, x509.ExtKeyUsageClientAuth)}
	if err := ValidateClientsAuthenticationCertificate(certificate); err != nil {
		t.Fatalf("Took %s error instead nil\n", err)
	}
}

func TestHexIdentifierConverter_ConvertLength1(t *testing.T) {
	identifier := []byte{1}
	result, err := HexIdentifierConverter{}.Convert(identifier)
	if err != nil {
		t.Fatal(err)
	}
	expectedResult := []byte(hex.EncodeToString(append(hexStaticPrefix, identifier...)))
	if !bytes.Equal(result, expectedResult) {
		t.Fatal("Incorrect converted value for identifier with length==1")
	}
}
func TestHexIdentifierConverter_ConvertLength128(t *testing.T) {
	identifier := make([]byte, 128)
	if _, err := rand.Read(identifier); err != nil {
		t.Fatal(err)
	}
	result, err := HexIdentifierConverter{}.Convert(identifier)
	if err != nil {
		t.Fatal(err)
	}
	expectedResult := []byte(hex.EncodeToString(identifier))
	if !bytes.Equal(result, expectedResult) {
		t.Fatal("Incorrect converted value for identifier with length == 128, when should be the same value in hex format")
	}
}
func TestHexIdentifierConverter_ConvertLengthLongerThan128(t *testing.T) {
	identifier := make([]byte, 129)
	if _, err := rand.Read(identifier); err != nil {
		t.Fatal(err)
	}
	result, err := HexIdentifierConverter{}.Convert(identifier)
	if err != nil {
		t.Fatal(err)
	}
	h := sha512.New()
	h.Write(identifier)
	expectedResult := []byte(hex.EncodeToString(h.Sum(nil)))
	if !bytes.Equal(result, expectedResult) {
		t.Fatal("Incorrect converted value for identifier with length > 128, when should be the hex value after sha512")
	}
}
