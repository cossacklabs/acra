package grpc_api

import (
	"github.com/cossacklabs/acra/network"
	"golang.org/x/net/context"
)

// DecryptService aggregated interface of each grpc service
type DecryptService interface {
	ReaderServer
	WriterServer
}

// TLSDecryptServiceWrapper wraps DecryptService and replace clientID in requests with clientID from connection info
type TLSDecryptServiceWrapper struct {
	decryptor         DecryptService
	clientIDExtractor network.GRPCConnectionClientIDExtractor
}

// Encrypt encrypt with clientID from connection info
func (wrapper *TLSDecryptServiceWrapper) Encrypt(ctx context.Context, request *EncryptRequest) (*EncryptResponse, error) {
	clientID, err := wrapper.clientIDExtractor.ExtractClientID(ctx)
	if err != nil {
		return nil, err
	}
	request.ClientId = clientID
	return wrapper.decryptor.Encrypt(ctx, request)
}

// Decrypt encrypt with clientID from connection info
func (wrapper *TLSDecryptServiceWrapper) Decrypt(ctx context.Context, request *DecryptRequest) (*DecryptResponse, error) {
	clientID, err := wrapper.clientIDExtractor.ExtractClientID(ctx)
	if err != nil {
		return nil, err
	}
	request.ClientId = clientID
	return wrapper.decryptor.Decrypt(ctx, request)
}

// NewTLSDecryptServiceWrapper return new service wrapper which use clientID from TLS certificates
func NewTLSDecryptServiceWrapper(clientIDExtractor network.GRPCConnectionClientIDExtractor, service DecryptService) (*TLSDecryptServiceWrapper, error) {
	return &TLSDecryptServiceWrapper{service, clientIDExtractor}, nil
}
