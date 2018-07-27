// Package network contains network utils for establishing secure session, for listening connections.
//
package network

import (
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
)

// ConnectionManager counts connections and close them
type ConnectionManager struct {
	*sync.WaitGroup
	mutex       *sync.Mutex
	Counter     int
	connections map[net.Conn]bool
}

// NewConnectionManager returns new ConnectionManager
func NewConnectionManager() *ConnectionManager {
	cm := &ConnectionManager{}
	cm.WaitGroup = &sync.WaitGroup{}
	cm.connections = make(map[net.Conn]bool)
	cm.mutex = &sync.Mutex{}
	return cm
}

// Incr increases connections counter
func (cm *ConnectionManager) Incr() {
	cm.Counter++
	log.Debugf("ConnectionManager Added new connection")
	cm.WaitGroup.Add(1)
}

// Done marks connection as done, decreases connections counter
func (cm *ConnectionManager) Done() {
	cm.Counter--
	cm.WaitGroup.Done()
}

// AddConnection adds new connection, increases connections counter
func (cm *ConnectionManager) AddConnection(conn net.Conn) error {
	cm.mutex.Lock()
	cm.Incr()
	cm.connections[conn] = true
	cm.mutex.Unlock()
	return nil
}

// RemoveConnection removes connection, marks it done, decreases connections counter
func (cm *ConnectionManager) RemoveConnection(conn net.Conn) error {
	cm.mutex.Lock()
	delete(cm.connections, conn)
	cm.Done()
	cm.mutex.Unlock()
	return nil
}

// CloseConnections close all available connections and return first occurred error
func (cm *ConnectionManager) CloseConnections() error {
	// lock for map read
	cm.mutex.Lock()
	var outErr error
	for connection := range cm.connections {
		if err := connection.Close(); err != nil {
			outErr = err
		}
	}
	cm.mutex.Unlock()
	return outErr
}
