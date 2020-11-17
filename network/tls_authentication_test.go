package network

import (
	"crypto/x509"
	"testing"
)

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
		KeyUsage: invalidKeyUsage | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: invalidExtKeyUsage}
	if err := ValidateClientsAuthenticationCertificate(certificate); err != nil {
		t.Fatalf("Took %s error instead nil\n", err)
	}

	// test only with correct ExtKeyUsage
	certificate = &x509.Certificate{
		KeyUsage: invalidKeyUsage,
		ExtKeyUsage: append(invalidExtKeyUsage, x509.ExtKeyUsageClientAuth)}
	if err := ValidateClientsAuthenticationCertificate(certificate); err != nil {
		t.Fatalf("Took %s error instead nil\n", err)
	}

	// test only with correct ExtKeyUsage
	certificate = &x509.Certificate{
		KeyUsage: invalidKeyUsage | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: append(invalidExtKeyUsage, x509.ExtKeyUsageClientAuth)}
	if err := ValidateClientsAuthenticationCertificate(certificate); err != nil {
		t.Fatalf("Took %s error instead nil\n", err)
	}

}
