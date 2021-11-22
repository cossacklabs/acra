package grpc_api

import (
	"context"
	"github.com/cossacklabs/acra/network"
	"google.golang.org/grpc/peer"
)

// DecryptService aggregated interface of each grpc service
type DecryptService interface {
	ReaderServer
	WriterServer
	TokenizatorServer
	ReaderSymServer
	WriterSymServer
	SearchableEncryptionServer
}

// TLSDecryptServiceWrapper wraps DecryptService and replace clientID in requests with clientID from connection info
type TLSDecryptServiceWrapper struct {
	decryptor            DecryptService
	tlsClientIDExtractor network.TLSClientIDExtractor
}

func getClientID(ctx context.Context, extractor network.TLSClientIDExtractor) ([]byte, error) {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok {
		return nil, network.ErrCantExtractClientID
	}
	return network.GetClientIDFromAuthInfo(peerInfo.AuthInfo, extractor)
}

// Encrypt encrypt with clientID from connection info
func (wrapper *TLSDecryptServiceWrapper) Encrypt(ctx context.Context, request *EncryptRequest) (*EncryptResponse, error) {
	clientID, err := getClientID(ctx, wrapper.tlsClientIDExtractor)
	if err != nil {
		return nil, err
	}
	request.ClientId = clientID
	return wrapper.decryptor.Encrypt(ctx, request)
}

// Decrypt encrypt with clientID from connection info
func (wrapper *TLSDecryptServiceWrapper) Decrypt(ctx context.Context, request *DecryptRequest) (*DecryptResponse, error) {
	clientID, err := getClientID(ctx, wrapper.tlsClientIDExtractor)
	if err != nil {
		return nil, err
	}
	request.ClientId = clientID
	return wrapper.decryptor.Decrypt(ctx, request)
}

// Tokenize encrypt with clientID from connection info
func (wrapper *TLSDecryptServiceWrapper) Tokenize(ctx context.Context, request *TokenizeRequest) (*TokenizeResponse, error) {
	clientID, err := getClientID(ctx, wrapper.tlsClientIDExtractor)
	if err != nil {
		return nil, err
	}
	request.ClientId = clientID
	return wrapper.decryptor.Tokenize(ctx, request)
}

// Detokenize encrypt with clientID from connection info
func (wrapper *TLSDecryptServiceWrapper) Detokenize(ctx context.Context, request *TokenizeRequest) (*TokenizeResponse, error) {
	clientID, err := getClientID(ctx, wrapper.tlsClientIDExtractor)
	if err != nil {
		return nil, err
	}
	request.ClientId = clientID
	return wrapper.decryptor.Detokenize(ctx, request)
}

// DecryptSym encrypt with clientID from connection info
func (wrapper *TLSDecryptServiceWrapper) DecryptSym(ctx context.Context, request *DecryptSymRequest) (*DecryptSymResponse, error) {
	clientID, err := getClientID(ctx, wrapper.tlsClientIDExtractor)
	if err != nil {
		return nil, err
	}
	request.ClientId = clientID
	return wrapper.decryptor.DecryptSym(ctx, request)
}

// EncryptSym encrypt with clientID from connection info
func (wrapper *TLSDecryptServiceWrapper) EncryptSym(ctx context.Context, request *EncryptSymRequest) (*EncryptSymResponse, error) {
	clientID, err := getClientID(ctx, wrapper.tlsClientIDExtractor)
	if err != nil {
		return nil, err
	}
	request.ClientId = clientID
	return wrapper.decryptor.EncryptSym(ctx, request)
}

// EncryptSearchable encrypt with clientID from connection info
func (wrapper *TLSDecryptServiceWrapper) EncryptSearchable(ctx context.Context, request *SearchableEncryptionRequest) (*SearchableEncryptionResponse, error) {
	clientID, err := getClientID(ctx, wrapper.tlsClientIDExtractor)
	if err != nil {
		return nil, err
	}
	request.ClientId = clientID
	return wrapper.decryptor.EncryptSearchable(ctx, request)
}

// DecryptSearchable encrypt with clientID from connection info
func (wrapper *TLSDecryptServiceWrapper) DecryptSearchable(ctx context.Context, request *SearchableDecryptionRequest) (*SearchableDecryptionResponse, error) {
	clientID, err := getClientID(ctx, wrapper.tlsClientIDExtractor)
	if err != nil {
		return nil, err
	}
	request.ClientId = clientID
	return wrapper.decryptor.DecryptSearchable(ctx, request)
}

// EncryptSymSearchable encrypt with clientID from connection info
func (wrapper *TLSDecryptServiceWrapper) EncryptSymSearchable(ctx context.Context, request *SearchableSymEncryptionRequest) (*SearchableSymEncryptionResponse, error) {
	clientID, err := getClientID(ctx, wrapper.tlsClientIDExtractor)
	if err != nil {
		return nil, err
	}
	request.ClientId = clientID
	return wrapper.decryptor.EncryptSymSearchable(ctx, request)
}

// DecryptSymSearchable encrypt with clientID from connection info
func (wrapper *TLSDecryptServiceWrapper) DecryptSymSearchable(ctx context.Context, request *SearchableSymDecryptionRequest) (*SearchableSymDecryptionResponse, error) {
	clientID, err := getClientID(ctx, wrapper.tlsClientIDExtractor)
	if err != nil {
		return nil, err
	}
	request.ClientId = clientID
	return wrapper.decryptor.DecryptSymSearchable(ctx, request)
}

// GenerateQueryHash encrypt with clientID from connection info
func (wrapper *TLSDecryptServiceWrapper) GenerateQueryHash(ctx context.Context, request *QueryHashRequest) (*QueryHashResponse, error) {
	clientID, err := getClientID(ctx, wrapper.tlsClientIDExtractor)
	if err != nil {
		return nil, err
	}
	request.ClientId = clientID
	return wrapper.decryptor.GenerateQueryHash(ctx, request)
}

// NewTLSDecryptServiceWrapper return new service wrapper which use clientID from TLS certificates
func NewTLSDecryptServiceWrapper(service DecryptService, tlsClientIDExtractor network.TLSClientIDExtractor) (*TLSDecryptServiceWrapper, error) {
	return &TLSDecryptServiceWrapper{service, tlsClientIDExtractor}, nil
}
