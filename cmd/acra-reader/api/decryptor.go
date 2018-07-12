package api

import (
	context "golang.org/x/net/context"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/themis/gothemis/keys"
)

type DecryptGRPCService struct {
	keystorage keystore.KeyStore
}

func NewDecryptGRPCService(keystorage keystore.KeyStore) (*DecryptGRPCService, error) {
	return &DecryptGRPCService{keystorage: keystorage}, nil
}

func (service *DecryptGRPCService) Decrypt(ctx context.Context, request *DecryptRequest) (*DecryptResponse, error) {
	var privateKey *keys.PrivateKey
	var err error
	var decryptionContext []byte = nil
	if len(request.ZoneId) != 0 {
		privateKey, err = service.keystorage.GetZonePrivateKey(request.ZoneId)
		decryptionContext = request.ZoneId
	} else {
		privateKey, err = service.keystorage.GetServerDecryptionPrivateKey(request.ClientId)
	}
	if err != nil {
		return nil, err
	}
	data, err := base.DecryptAcrastruct(request.Acrastruct, privateKey, decryptionContext)
	if err != nil {
		return nil, err
	}
	return &DecryptResponse{Data: data}, nil
}
