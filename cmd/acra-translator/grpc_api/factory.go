package grpc_api

import (
	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	keystore2 "github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	tokenCommon "github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// GRPCServerFactory used to create new grpc.Server instances configured to implement AcraTranslator methods
type GRPCServerFactory struct {
	tokenizer tokenCommon.Pseudoanonymizer
	keystore  keystore2.TranslationKeyStore
}

// NewgRPCServerFactory return new GRPCServerFactory
func NewgRPCServerFactory(tokenizer tokenCommon.Pseudoanonymizer, keystore keystore2.TranslationKeyStore) (*GRPCServerFactory, error) {
	return &GRPCServerFactory{tokenizer: tokenizer, keystore: keystore}, nil
}

// New return new grpc.Server with AcraTranslator methods as gRPC service
func (g *GRPCServerFactory) New(data *common.TranslatorData, opts ...grpc.ServerOption) (*grpc.Server, error) {
	var newService DecryptService
	var err error
	serviceImplementation, err := common.NewTranslatorService(data, g.tokenizer)
	if err != nil {
		logrus.WithError(err).Errorln("Can't initialize service implementation")
		return nil, err
	}
	// wrap service with metrics that track time of execution
	serviceWithMetrics, err := common.NewPrometheusServiceWrapper(serviceImplementation, common.GrpcRequestType)
	if err != nil {
		return nil, err
	}

	newService, err = NewTranslatorService(serviceWithMetrics, data, g.tokenizer, g.keystore)
	if err != nil {
		return nil, err
	}

	if data.UseConnectionClientID {
		logrus.Infoln("Wrap gRPC service to use clientID from connection")
		newService, err = NewTLSDecryptServiceWrapper(newService, data.TLSClientIDExtractor)
		if err != nil {
			logrus.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleGRPCConnection).
				Errorln("Can't wrap gRPC service with TLS wrapper")
			return nil, err
		}
	}

	opts = append(opts, grpc.ConnectionTimeout(network.DefaultNetworkTimeout))
	grpcServer := grpc.NewServer(opts...)
	RegisterReaderServer(grpcServer, newService)
	RegisterWriterServer(grpcServer, newService)
	RegisterTokenizatorServer(grpcServer, newService)
	RegisterSearchableEncryptionServer(grpcServer, newService)
	RegisterReaderSymServer(grpcServer, newService)
	RegisterWriterSymServer(grpcServer, newService)
	// Register reflection service on gRPC server.
	reflection.Register(grpcServer)
	return grpcServer, nil
}
