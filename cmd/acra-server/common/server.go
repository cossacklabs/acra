package common

import (
	"context"
	"errors"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/network"
	log "github.com/sirupsen/logrus"
	"os"
	"sync"
	"time"
)

// TimeoutToExit timeout for exit operation for SServer component
const TimeoutToExit = time.Second

// ErrShutdownAttemptWithoutExit is an error occurred when context cancelled but Exit function is not called
var ErrShutdownAttemptWithoutExit = errors.New("unexpected way to shutdown service")

// NewEEAcraServerMainComponent creates new SServer wrapper
func NewEEAcraServerMainComponent(config *Config, proxyFactory base.ProxyFactory, errorChan chan os.Signal, restartChan chan os.Signal) (*SServer, error) {
	return &SServer{
		config:                config,
		connectionManager:     network.NewConnectionManager(),
		errorSignalChannel:    errorChan,
		restartSignalsChannel: restartChan,
		proxyFactory:          proxyFactory,
		stopListenersSignal:   make(chan bool),
		errCh:                 make(chan error),
	}, nil
}

// Exit exits SServer by sending the input error to the internal channel
// that is listened in Start function
func (server *SServer) Exit(err error) {
	server.errCh <- err
	close(server.errCh)
}

// StartServer starts SServer
func (server *SServer) StartServer(parentContext context.Context, group *sync.WaitGroup, withZones, enableHTTPApi bool) error {
	if withZones || enableHTTPApi {
		group.Add(1)
		go func() {
			defer group.Done()
			server.StartCommands(parentContext)
		}()
	}
	group.Add(1)
	go func() {
		defer group.Done()
		server.Start(parentContext)
	}()

	// here we block execution until global context is done.
	// Start and StartCommands also blocks on it so we are in sync when shutdown occurs
	<-parentContext.Done()

	return server.checkShutdownViaExitFunc()
}

// StartServerFromFileDescriptor starts SServer with appropriate file descriptors
func (server *SServer) StartServerFromFileDescriptor(parentContext context.Context, group *sync.WaitGroup, withZones, enableHTTPApi bool, fdAcra, fdAPI uintptr) error {
	if withZones || enableHTTPApi {
		group.Add(1)
		go func() {
			defer group.Done()
			server.StartCommandsFromFileDescriptor(parentContext, fdAPI)
		}()
	}
	group.Add(1)
	go func() {
		defer group.Done()
		server.StartFromFileDescriptor(parentContext, fdAcra)
	}()

	// here we block execution until global context is done.
	// StartFromFileDescriptor and StartCommandsFromFileDescriptor also blocks on it so we are in sync when shutdown occurs
	<-parentContext.Done()

	return server.checkShutdownViaExitFunc()
}

func (server *SServer) checkShutdownViaExitFunc() error {
	// server has been stopped by global `cancel`. Here we check if some errors occurred. If so, it will exit with non-zero code
	select {
	case <-time.After(TimeoutToExit):
		log.Errorf("Unexpected way to shutdown the service (Exit func is not called). Exit with non-zero status after timeout")
		return ErrShutdownAttemptWithoutExit
	case err := <-server.errCh:
		if err != nil {
			return err
		}
		return nil
	}
}
