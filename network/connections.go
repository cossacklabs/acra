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
	connections map[uintptr]net.Conn
}

func NewConnectionManager() *ConnectionManager {
	cm := &ConnectionManager{}
	cm.WaitGroup = &sync.WaitGroup{}
	cm.connections = make(map[uintptr]net.Conn)
	cm.mutex = &sync.Mutex{}
	return cm
}
func (manager *ConnectionManager) getConnectionIdentifier(connection net.Conn) (uintptr, error) {
	return GetConnectionDescriptor(connection)
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

func (cm *ConnectionManager) AddConnection(conn net.Conn) error {
	ident, err := cm.getConnectionIdentifier(conn)
	if err != nil {
		return err
	}
	cm.mutex.Lock()
	cm.connections[ident] = conn
	cm.Incr()
	cm.mutex.Unlock()
	return nil
}

func (cm *ConnectionManager) RemoveConnection(conn net.Conn) error {
	ident, err := cm.getConnectionIdentifier(conn)
	if err != nil {
		return err
	}
	cm.mutex.Lock()
	delete(cm.connections, ident)
	cm.Done()
	cm.mutex.Unlock()
	return nil
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
