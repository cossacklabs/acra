package network

import (
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
)

type ConnectionManager struct {
	*sync.WaitGroup
	mutex       *sync.Mutex
	Counter     int
	connections map[net.Conn]bool
}

func NewConnectionManager() *ConnectionManager {
	cm := &ConnectionManager{}
	cm.WaitGroup = &sync.WaitGroup{}
	cm.connections = make(map[net.Conn]bool)
	cm.mutex = &sync.Mutex{}
	return cm
}

func (cm *ConnectionManager) Incr() {
	cm.Counter++
	log.Debugf("ConnectionManager.Add")
	cm.WaitGroup.Add(1)
}

func (cm *ConnectionManager) Done() {
	cm.Counter--
	cm.WaitGroup.Done()
}

func (cm *ConnectionManager) AddConnection(conn net.Conn) error {
	cm.mutex.Lock()
	cm.Incr()
	cm.connections[conn] = true
	cm.mutex.Unlock()
	return nil
}

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
