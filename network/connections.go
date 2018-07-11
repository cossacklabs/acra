package network

import (
	log "github.com/sirupsen/logrus"
	"net"
	"sync"
)

type ConnectionManager struct {
	*sync.WaitGroup
	mutex       *sync.Mutex
	Counter     int
	connections map[string]net.Conn
}

func NewConnectionManager() *ConnectionManager {
	cm := &ConnectionManager{}
	cm.WaitGroup = &sync.WaitGroup{}
	cm.connections = make(map[string]net.Conn)
	cm.mutex = &sync.Mutex{}
	return cm
}
func (manager *ConnectionManager) getConnectionAddress(connection net.Conn) string {
	return connection.RemoteAddr().String()
}

func (cm *ConnectionManager) Incr() {
	cm.Counter += 1
	log.Debugf("ConnectionManager.Add")
	cm.WaitGroup.Add(1)
}

func (cm *ConnectionManager) Done() {
	cm.Counter--
	cm.WaitGroup.Done()
}

func (cm *ConnectionManager) AddConnection(conn net.Conn) {
	cm.mutex.Lock()
	cm.connections[cm.getConnectionAddress(conn)] = conn
	cm.Incr()
	cm.mutex.Unlock()
}

func (cm *ConnectionManager) RemoveConnection(conn net.Conn) {
	cm.mutex.Lock()
	delete(cm.connections, cm.getConnectionAddress(conn))
	cm.Done()
	cm.mutex.Unlock()
}

// CloseConnections close all available connections and return first occurred error
func (cm *ConnectionManager) CloseConnections() error {
	// lock for map read
	cm.mutex.Lock()
	var outErr error
	for _, connection := range cm.connections {
		if err := connection.Close(); err != nil {
			outErr = err
		}
	}
	cm.mutex.Unlock()
	return outErr
}
