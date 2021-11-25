package grpc_api

import (
	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// NewServer return new grpc.Server with AcraTranslator methods as gRPC service
func NewServer(data *common.TranslatorData, connectionWrapper network.GRPCConnectionWrapper) (*grpc.Server, error) {
	opts := []grpc.ServerOption{grpc.Creds(connectionWrapper)}
	var newService DecryptService
	var err error
	serviceImplementation, err := common.NewTranslatorService(data)
	if err != nil {
		logrus.WithError(err).Errorln("Can't initialize service implementation")
		return nil, err
	}
	// wrap service with metrics that track time of execution
	serviceWithMetrics, err := common.NewPrometheusServiceWrapper(serviceImplementation, common.GrpcRequestType)
	if err != nil {
		return nil, err
	}

	newService, err = NewTranslatorService(serviceWithMetrics, data)
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
	OngRPCServerInit(grpcServer, data, newService)
	// Register reflection service on gRPC server.
	reflection.Register(grpcServer)
	return grpcServer, nil
}
