package network

import (
	"sync"
	"net"
	log "github.com/sirupsen/logrus"
)

type ConnectionManager struct {
	*sync.WaitGroup
	Counter int
	connections []*net.Conn
}

func NewConnectionManager() *ConnectionManager {
	cm := &ConnectionManager{}
	cm.WaitGroup = &sync.WaitGroup{}
	return cm
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

func (cm *ConnectionManager) AddConnection(conn *net.Conn) {
	cm.connections = append(cm.connections, conn)
}
