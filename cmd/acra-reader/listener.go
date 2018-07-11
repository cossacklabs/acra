// Copyright 2018, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"net"

	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
)

type ListenTask struct {
	ConnectionString          string
	ConnectionsChannel        chan<- net.Conn
	WrappedConnectionsChannel chan<- net.Conn
	errCh                     chan error
	net.Listener
}

func (task *ListenTask) addAcceptedConnection(connection net.Conn) {
	task.ConnectionsChannel <- connection
}

func (task *ListenTask) ErrorChannel() chan error {
	return task.errCh
}

func (task *ListenTask) SetListener(listener net.Listener) {
	task.Listener = listener
}

func NewListenTask(connectionString string, connectionsChannel, wrappedConnectionsChannel chan net.Conn) (*ListenTask, error) {
	return &ListenTask{ConnectionString: connectionString, ConnectionsChannel: connectionsChannel, WrappedConnectionsChannel: wrappedConnectionsChannel, errCh: make(chan error, 1)}, nil
}

// AcceptConnections return channel which will produce new connections from listener in background goroutine
func AcceptConnections(parentContext context.Context, connectionString string, errCh chan<- error) (<-chan net.Conn, error) {
	logger := logging.GetLoggerFromContext(parentContext)
	listenContext, cancel := context.WithCancel(parentContext)
	connectionChannel := make(chan net.Conn)
	listener, err := network.Listen(connectionString)
	if err != nil {
		return nil, err
	}

	// run goroutine that just accept connections and return them and stop on error. you can stop it by closing listener
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			logger.WithError(err).Errorln("Error on accept connection")
			errCh <- err
			cancel()
			return
		}
		connectionChannel <- conn
	}()

	// wait Done signal from caller or from "accept" goroutine and stop listener
	go func() {
		<-listenContext.Done()
		logger.WithError(listenContext.Err()).Infoln("Close listener")
		// stop listener and goroutine that produce connections from listener
		err := listener.Close()
		if err != nil {
			logger.WithError(err).Errorln("Error on closing listener")
		}
	}()
	return connectionChannel, nil
}
