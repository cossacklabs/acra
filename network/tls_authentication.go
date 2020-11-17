package network

import (
	"crypto/x509"
	"errors"
)

// Set of errors related to peer certificate validation
var (
	ErrNoPeerCertificate            = errors.New("no peer tls certificate")
	ErrCACertificateUsed            = errors.New("used CA certificate for authentication")
	ErrMissedAuthenticationKeyUsage = errors.New("peer certificate doesn't have DigitalSignature key usage or ClientAuth ExtKeyUsage values")
)

// ValidateClientsAuthenticationCertificate check that peer's certificate acceptable to use for authentication purpose
// Check that KeyUsage has DigitalSignature mask or ClientAuth set in ExtKeyUsage list, deny CA certificates to use for peer authentication
func ValidateClientsAuthenticationCertificate(certificate *x509.Certificate) error {
	if certificate == nil {
		return ErrNoPeerCertificate
	}
	if certificate.IsCA {
		return ErrCACertificateUsed
	}
	// do we found any authentication keyUsage from KeyUsage field or from ExtKeyUsage parameters
	// certificate may define any of them or both
	definedAnyAuthenticationKeyUsage := false
	keyUsageDefined := certificate.KeyUsage != 0
	authenticationKeyUsage := certificate.KeyUsage&x509.KeyUsageDigitalSignature == 1
	if keyUsageDefined && authenticationKeyUsage {
		definedAnyAuthenticationKeyUsage = true
	}
	extKeyUsageDefined := len(certificate.ExtKeyUsage) != 0
	if extKeyUsageDefined {
		for _, usage := range certificate.ExtKeyUsage {
			if usage == x509.ExtKeyUsageClientAuth {
				definedAnyAuthenticationKeyUsage = true
				break
			}
		}
	}
	if !definedAnyAuthenticationKeyUsage {
		return ErrMissedAuthenticationKeyUsage
	}
	return nil
}
