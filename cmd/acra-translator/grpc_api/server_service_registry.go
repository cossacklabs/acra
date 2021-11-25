package grpc_api

import (
	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	"google.golang.org/grpc"
	"sync"
)

// GRPCServerSubscriber declares callbacks for gRPC server subscribers
type GRPCServerSubscriber interface {
	OnServerInit(server *grpc.Server, data *common.TranslatorData, service DecryptService)
}

// global registry of gRPC server subscribers
var grpcServerSubscribers = make([]GRPCServerSubscriber, 0, 8)
var lock = sync.Mutex{}

// AddgRPCServerSubscriber register callback for gRPC server
func AddgRPCServerSubscriber(subscriber GRPCServerSubscriber) {
	lock.Lock()
	grpcServerSubscribers = append(grpcServerSubscribers, subscriber)
	lock.Unlock()
}

// OngRPCServerInit call all registered callbacks on gRPC server initialization
func OngRPCServerInit(server *grpc.Server, data *common.TranslatorData, service DecryptService) {
	lock.Lock()
	defer lock.Unlock()
	for _, subscriber := range grpcServerSubscribers {
		subscriber.OnServerInit(server, data, service)
	}
}
