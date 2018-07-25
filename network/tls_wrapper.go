package network

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"

	"errors"
	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"
)

type TLSConnectionWrapper struct {
	config   *tls.Config
	clientID []byte
}

var ErrEmptyTLSConfig = errors.New("empty TLS config")

func NewTLSConnectionWrapper(clientID []byte, config *tls.Config) (*TLSConnectionWrapper, error) {
	return &TLSConnectionWrapper{config: config, clientID: clientID}, nil
}

func (wrapper *TLSConnectionWrapper) WrapClient(id []byte, conn net.Conn) (net.Conn, error) {
	tlsConn := tls.Client(conn, wrapper.config)
	err := tlsConn.Handshake()
	if err != nil {
		return conn, err
	}
	return tlsConn, nil
}
func (wrapper *TLSConnectionWrapper) WrapServer(conn net.Conn) (net.Conn, []byte, error) {
	tlsConn := tls.Server(conn, wrapper.config)
	err := tlsConn.Handshake()
	if err != nil {
		return conn, nil, err
	}
	return tlsConn, wrapper.clientID, nil
}

func NewTLSConfig(serverName string, caPath, keyPath, crtPath string, authType tls.ClientAuthType) (*tls.Config, error) {
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
			log.Errorln("Can't add CA certificate from PEM")
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
	return &tls.Config{
		RootCAs:      roots,
		ClientCAs:    roots,
		Certificates: certificates,
		ServerName:   serverName,
		ClientAuth:   authType}, nil
}
