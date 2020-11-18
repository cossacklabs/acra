package network

import (
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"github.com/cossacklabs/acra/keystore"
)

// CertificateIdentifierExtractor interface for implementations which should return identifier used for client's identification
type CertificateIdentifierExtractor interface {
	GetCertificateIdentifier(certificate *x509.Certificate) ([]byte, error)
}

// CommonNameExtractor implementation for CertificateIdentifierExtractor interface, which return CommonName as client's identifier
type CommonNameExtractor struct{}

// GetCertificateIdentifier return Subject.String() as client's identifier by tls certificate
func (e CommonNameExtractor) GetCertificateIdentifier(certificate *x509.Certificate) ([]byte, error) {
	if certificate == nil {
		return nil, ErrNoPeerCertificate
	}
	return []byte(certificate.Subject.String()), nil
}

// SerialNumberExtractor implementation for CertificateIdentifierExtractor interface, which return SerialNumber of certificate as client's identifier
type SerialNumberExtractor struct{}

// GetCertificateIdentifier return SerialNumber as client's identifier by tls certificate
func (e SerialNumberExtractor) GetCertificateIdentifier(certificate *x509.Certificate) ([]byte, error) {
	if certificate == nil {
		return nil, ErrNoPeerCertificate
	}
	return certificate.SerialNumber.Bytes(), nil
}

// ErrEmptyIdentifier used when passed empty identifier with zero length
var ErrEmptyIdentifier = errors.New("empty identifier")

// IdentifierConverter converts identifiers from x509 certificates to clientID format acceptable by keystore, pass keystore.ValidateID check
type IdentifierConverter interface {
	Convert(identifier []byte)([]byte, error)
}

// HexIdentifierConverter converts identifiers to hex value
type HexIdentifierConverter struct {}
var hexStaticPrefix = []byte{0}
// Convert identifier to hex value. If len(identifier) == 1 then 0 inserted as start of identifier to match minimal length
// of clientID 4 bytes. If len(identifier) > (keystore.MaxClientIDLength / 2) than it longer than max acceptable length of clientID in hex format (256)
// In such case identifier passed through SHA512 and then converted to hex with 128 (64 * 2) bytes length
func (c HexIdentifierConverter) Convert(identifier[]byte)([]byte, error){
	var out []byte
	if len(identifier) == 1 {
		out = make([]byte, hex.EncodedLen(len(identifier) + len(hexStaticPrefix)))
		identifier = append(hexStaticPrefix, identifier...)
	} else if len(identifier) > (keystore.MaxClientIDLength / 2) {
		out = make([]byte, hex.EncodedLen(sha512.Size))
		h := sha512.New()
		if _, err := h.Write(identifier); err != nil {
			return nil, err
		}
		identifier = h.Sum(nil)
	} else {
		out = make([]byte, hex.EncodedLen(len(identifier)))
	}
	hex.Encode(out, identifier)
	return out, nil
}

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
