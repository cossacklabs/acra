package network

import "strings"

// set of suggestions to TLS/x509 related errors
const (
	DatabaseSideSNIErrorSuggestion = "" +
		"Acra-server configured with --db_host=<db_host> and --tls_database_sni=<sni> that don't " +
		"match \"Subject Alternative Name\" in database's certificate. Check which domains are present in the" +
		"certificate for database with command: \"openssl x509 -noout -ext subjectAltName -in <cert_path>>\" " +
		"and set one of the domains as acra-server's parameter \"--tls_database_sni\""
	DatabaseSideUnknownCAErrorSuggestions = "" +
		"The database sent certificate that cannot be verified by CA certificate set in \"--tls_database_ca\" (\"--tls_ca\") " +
		"acra-server's parameters. Set the same CA certificate that you use for the database."
	ClientSideBadMacErrorSuggestion = "" +
		"Possible cause of the error is that the client application cannot verify acra-server's certificate. The application or its DB driver haven't " +
		"CA certificate related to acra-server's certificate. Configure your application to use acra-server's CA too."
	ClientSideUnknownCAErrorSuggestion = "" +
		"The client app has sent a certificate signed by unknown CA. Configure acra-server to use CA certificate used to sign client's " +
		"certificate with parameter \"--tls_client_ca=<path>\"."
	ClientSideNoCertificateErrorSuggestion = "The client application doesn't send TLS certificate. Check that the application configured with appropriate " +
		"SSLMODE that turn on usage TLS for connections, configured private key with certificate. Additionally, check that private " +
		"key has 0600 permissions, and the database supports TLS."
	CRLCheckErrorSuggestion = "Ensure that the CRL server is up and responding. Acra-server uses CRL server's configured with " +
		"--tls_crl_client_url | --tls_crl_database_url parameters and specified in client's/databases's " +
		"certificates. You can get CRL urls from certificates with command: \"openssl x509 -noout -ext crlDistributionPoints -in <path>\". " +
		"For test purposes you can disable CRL checks with \"--tls_crl_from_cert=ignore\" and empty " +
		"\"--tls_crl_url=\" parameters for acra-server."
	OCSPCheckErrorSuggestion = "Check that the OCSP server is up and responding. Acra-server uses OCSP server's configured with " +
		"--tls_ocsp_client_url | --tls_ocsp_database_url parameters and specified in client's/databases's " +
		"certificates. You can get OCSP urls from certificates with command: \"openssl x509 -noout -ocsp_uri -in <path>\". " +
		"For test purposes you can disable OCSP checks with \"--tls_ocsp_from_cert=ignore\" and empty " +
		"\"--tls_ocsp_url=\" parameters for acra-server."
)

// IsSNIError return true if error related to x509 error with SAN/SNI mismatch
func IsSNIError(err error) bool {
	// due to tls package uses errors.New/fmt.Errorf error generation, we can only compare string decsription
	return strings.HasPrefix(err.Error(), "x509: certificate is valid for ")
}

// IsDatabaseUnknownCAError return true if error related to certificate's signature signed by unknown CA
func IsDatabaseUnknownCAError(err error) bool {
	return err.Error() == "x509: certificate signed by unknown authority"
}

// IsClientBadRecordMacError return true if error related to bad MAC on client side
func IsClientBadRecordMacError(err error) bool {
	return err.Error() == "local error: tls: bad record MAC"
}

// IsClientUnknownCAError return true if client's certificate signed by unknown CA
func IsClientUnknownCAError(err error) bool {
	return err.Error() == "tls: failed to verify client certificate: x509: certificate signed by unknown authority"
}

// IsMissingClientCertificate return true if error related to missing client's certificate
func IsMissingClientCertificate(err error) bool {
	return err.Error() == "tls: client didn't provide a certificate"
}
