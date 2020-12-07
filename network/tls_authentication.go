package network

import (
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"hash"
)

// Set of constants with
const (
	IdentifierExtractorTypeDistinguishedName = "distinguished_name"
	IdentifierExtractorTypeSerialNumber      = "serial_number"
)

// ErrInvalidIdentifierExtractorType return when used invalid value of identifier extractor type
var ErrInvalidIdentifierExtractorType = errors.New("invalid identifier extractor type")

// NewIdentifierExtractorByType return new CertificateIdentifierExtractor by type
func NewIdentifierExtractorByType(extractorType string) (CertificateIdentifierExtractor, error) {
	switch extractorType {
	case IdentifierExtractorTypeDistinguishedName:
		return DistinguishedNameExtractor{}, nil
	case IdentifierExtractorTypeSerialNumber:
		return SerialNumberExtractor{}, nil
	default:
		return nil, ErrInvalidIdentifierExtractorType
	}
}

// CertificateIdentifierExtractor interface for implementations which should return identifier used for client's identification
type CertificateIdentifierExtractor interface {
	GetCertificateIdentifier(certificate *x509.Certificate) ([]byte, error)
}

// DistinguishedNameExtractor implementation for CertificateIdentifierExtractor interface, which return CommonName as client's identifier
type DistinguishedNameExtractor struct{}

// GetCertificateIdentifier return pkix.Name.String() which is DN in format according to RFC2253 (https://tools.ietf.org/html/rfc2253)
// To get DN in CLI with openssl: openssl x509 -in client.crt -subject -noout -nameopt RFC2253  | sed 's/subject=//'
func (e DistinguishedNameExtractor) GetCertificateIdentifier(certificate *x509.Certificate) ([]byte, error) {
	if certificate == nil {
		return nil, ErrNoPeerCertificate
	}
	id := []byte(certificate.Subject.String())
	if len(id) == 0 {
		return nil, ErrEmptyIdentifier
	}
	return id, nil
}

// SerialNumberExtractor implementation for CertificateIdentifierExtractor interface, which return SerialNumber of certificate as client's identifier
type SerialNumberExtractor struct{}

// GetCertificateIdentifier return SerialNumber as client's identifier by tls certificate
func (e SerialNumberExtractor) GetCertificateIdentifier(certificate *x509.Certificate) ([]byte, error) {
	if certificate == nil {
		return nil, ErrNoPeerCertificate
	}
	if certificate.SerialNumber == nil {
		return nil, ErrEmptyIdentifier
	}
	return certificate.SerialNumber.Bytes(), nil
}

// ErrEmptyIdentifier used when passed empty identifier with zero length
var ErrEmptyIdentifier = errors.New("empty identifier")

// IdentifierConverter converts identifiers from x509 certificates to clientID format acceptable by keystore, pass keystore.ValidateID check
type IdentifierConverter interface {
	Convert(identifier []byte) ([]byte, error)
}

// hexIdentifierConverter converts identifiers to hex value as string in lower case
type hexIdentifierConverter struct {
	newHash func() hash.Hash
}

// NewDefaultHexIdentifierConverter return new hexIdentifierConverter with sha512 as hash function used to fit output into acceptable size
func NewDefaultHexIdentifierConverter() (*hexIdentifierConverter, error) {
	return &hexIdentifierConverter{newHash: sha512.New}, nil
}

// Convert identifier to hex value in lower case. If len(identifier) == 1 then 0 inserted as start of identifier to match minimal length
// of clientID 4 bytes. If len(identifier) > (keystore.MaxClientIDLength / 2) than it longer than max acceptable length of clientID in hex format (256)
// In such case identifier passed through SHA512 and then converted to hex with 128 (64 * 2) bytes length
func (c hexIdentifierConverter) Convert(identifier []byte) ([]byte, error) {
	out := make([]byte, hex.EncodedLen(sha512.Size))
	h := c.newHash()
	if _, err := h.Write(identifier); err != nil {
		return nil, err
	}
	identifier = h.Sum(nil)
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
