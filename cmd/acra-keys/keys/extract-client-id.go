package keys

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/network"
)

// ExtractClientIDParams are parameters of "acra-keys extract-client-id" subcommand.
type ExtractClientIDParams interface {
	TLSClientCert() string
	TLSIdentifierExtractorType() string
}

// CommonExtractClientIDParameters is a mix-in of command line parameters for extracting clientID from TLS certificate.
type CommonExtractClientIDParameters struct {
	tlsClientCertOld, tlsClientCertNew, tlsIdentifierExtractorType string
	printJSON                                                      bool
}

// TLSClientCert returns path to TLS certificate path file to extract ID from.
func (p *CommonExtractClientIDParameters) TLSClientCert() string {
	if p.tlsClientCertOld != "" {
		return p.tlsClientCertOld
	}
	return p.tlsClientCertNew
}

// TLSIdentifierExtractorType returns TLS identifier extractor type based on which ID will be extracted.
func (p *CommonExtractClientIDParameters) TLSIdentifierExtractorType() string {
	return p.tlsIdentifierExtractorType
}

// PrintJSON tells if machine-readable JSON should be used.
func (p *CommonExtractClientIDParameters) PrintJSON() bool {
	return p.printJSON
}

// Register registers key formatting flags with the given flag set.
func (p *CommonExtractClientIDParameters) Register(flags *flag.FlagSet) {
	flags.BoolVar(&p.printJSON, "print_json", false, "use machine-readable JSON output")
	flags.StringVar(&p.tlsClientCertOld, "tls_cert", "", "Path to TLS certificate to use as client_id identifier. Deprecated since 0.96.0 use --tls_client_id_cert")
	flags.StringVar(&p.tlsClientCertNew, "tls_client_id_cert", "", "Path to TLS certificate to use as client_id identifier.")
	flags.StringVar(&p.tlsIdentifierExtractorType, "tls_identifier_extractor_type", network.IdentifierExtractorTypeDistinguishedName,
		fmt.Sprintf("Decide which field of TLS certificate to use as ClientID (%s). Default is %s.", strings.Join(network.IdentifierExtractorTypesList, "|"), network.IdentifierExtractorTypeDistinguishedName))
}

// ExtractClientIDSubcommand is the "acra-keys extract-client-id" subcommand.
type ExtractClientIDSubcommand struct {
	CommonExtractClientIDParameters

	flagSet *flag.FlagSet
}

// Name returns the same of this subcommand.
func (p *ExtractClientIDSubcommand) Name() string {
	return CmdExtractClientID
}

// GetFlagSet returns flag set of this subcommand.
func (p *ExtractClientIDSubcommand) GetFlagSet() *flag.FlagSet {
	return p.flagSet
}

// RegisterFlags registers command-line flags of "acra-keys import".
func (p *ExtractClientIDSubcommand) RegisterFlags() {
	p.flagSet = flag.NewFlagSet(CmdExtractClientID, flag.ContinueOnError)
	p.CommonExtractClientIDParameters.Register(p.flagSet)
	p.flagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Command \"%s\": extract clientID from TLS certificate\n", CmdExtractClientID)
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		cmd.PrintFlags(p.flagSet)
	}
}

// Parse command-line parameters of the subcommand.
func (p *ExtractClientIDSubcommand) Parse(arguments []string) error {
	err := cmd.ParseFlagsWithConfig(p.flagSet, arguments, DefaultConfigPath, ServiceName)
	if err != nil {
		return err
	}

	// TODO: use just tlsClientCertNew in 0.97.0
	if p.tlsClientCertOld == "" && p.tlsClientCertNew == "" {
		return ErrMissingTLSCertPath
	}

	if p.tlsClientCertNew != "" && p.tlsClientCertOld != "" {
		return ErrDuplicatedTLSCertPathFlags
	}

	return nil
}

// Execute this subcommand.
func (p *ExtractClientIDSubcommand) Execute() {
	clientID, err := ExtractClientID(p)
	if err != nil {
		log.WithError(err).Fatal("Failed to extract clientID from cert")
	}

	if err = p.printClientID(os.Stdout, clientID); err != nil {
		log.WithError(err).Fatal("Failed to print clientID")
	}
}

// ExtractClientID extract clientID based on ExtractClientIDParams.
func ExtractClientID(params ExtractClientIDParams) (string, error) {
	idConverter, err := network.NewDefaultHexIdentifierConverter()
	if err != nil {
		log.WithError(err).Errorln("Can't initialize identifier converter")
		return "", err
	}
	identifierExtractor, err := network.NewIdentifierExtractorByType(params.TLSIdentifierExtractorType())
	if err != nil {
		log.WithField("type", params.TLSIdentifierExtractorType()).WithError(err).Errorln("Can't initialize identifier extractor")
		return "", err
	}
	clientIDExtractor, err := network.NewTLSClientIDExtractor(identifierExtractor, idConverter)
	if err != nil {
		log.WithError(err).Errorln("Can't initialize clientID extractor")
		return "", err
	}
	pemCertificateFile, err := os.ReadFile(params.TLSClientCert())
	if err != nil {
		log.WithError(err).Errorln("Can't read TLS certificate")
		return "", err
	}
	block, _ := pem.Decode(pemCertificateFile)
	if block == nil {
		log.WithError(err).Errorln("Can't parse TLS certificate as PEM encoded file")
		return "", err
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.WithError(err).Errorln("Can't parse TLS certificate")
		return "", err
	}
	tlsClientID, err := clientIDExtractor.ExtractClientID(certificate)
	if err != nil {
		log.WithError(err).Errorln("Can't extract clientID from TLS certificate")
		return "", err
	}
	return string(tlsClientID), nil
}

func (p *ExtractClientIDSubcommand) printClientID(writer io.Writer, clientID string) error {
	if p.PrintJSON() {
		return printClientJSON(writer, clientID)
	}

	fmt.Fprintf(writer, "%s\n", clientID)
	return nil
}

func printClientJSON(writer io.Writer, clientID string) error {
	output := struct {
		ClientID string `json:"client_id"`
	}{
		ClientID: clientID,
	}

	json, err := json.Marshal(output)
	if err != nil {
		return err
	}
	json = append(json, byte('\n'))
	_, err = writer.Write(json)
	return err
}
