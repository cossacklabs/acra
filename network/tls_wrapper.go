package network

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"

	log "github.com/sirupsen/logrus"
)

type TLSConnectionWrapper struct {
	config   *tls.Config
	clientId []byte
}

func NewTLSConnectionWrapper(clientId []byte, config *tls.Config) (*TLSConnectionWrapper, error) {
	return &TLSConnectionWrapper{config: config, clientId: clientId}, nil
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
	return tlsConn, wrapper.clientId, nil
}

func NewTLSConfig(serverName string, caPath, keyPath, crtPath string) (*tls.Config, error) {
	roots := x509.NewCertPool()
	if caPath != "" {
		caPem, err := ioutil.ReadFile(caPath)
		if err != nil {
			log.WithError(err).Errorln("can't read root CA certificate")
			return nil, err
		}
		log.Debugln("add CA root certificate")
		if ok := roots.AppendCertsFromPEM(caPem); !ok {
			log.Errorln("can't add CA certificate")
			return nil, err
		}
	}
	cer, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		RootCAs:      roots,
		ClientCAs:    roots,
		Certificates: []tls.Certificate{cer},
		ServerName:   serverName,
		ClientAuth:   tls.RequireAndVerifyClientCert}, nil
}
