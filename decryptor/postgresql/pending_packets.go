/*
 * Copyright 2022, Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package postgresql

import (
	"container/list"
	"errors"
	"reflect"
	"sync"

	"github.com/jackc/pgx/v5/pgproto3"
	log "github.com/sirupsen/logrus"
)

// pendingPacketsList stores objects per their type and provides API similar to queue
type pendingPacketsList struct {
	mutex sync.RWMutex
	lists map[reflect.Type]*list.List
}

func newPendingPacketsList() *pendingPacketsList {
	return &pendingPacketsList{lists: make(map[reflect.Type]*list.List)}
}

// ErrUnsupportedPendingPacketType error after using unknown type of structure
var ErrUnsupportedPendingPacketType = errors.New("unsupported pending packet type")

// ErrRemoveFromEmptyPendingList error after trying to remove object from empty list
var ErrRemoveFromEmptyPendingList = errors.New("removing from empty pending list")

// Add packet to pending list of packets of this type
func (packets *pendingPacketsList) Add(packet interface{}) error {
	packets.mutex.Lock()
	defer packets.mutex.Unlock()

	switch packet.(type) {
	case *ParsePacket, *BindPacket, *ExecutePacket, *pgproto3.RowDescription, *pgproto3.ParameterDescription, queryPacket:
		packetType := reflect.TypeOf(packet)
		packetList, ok := packets.lists[packetType]
		if !ok {
			packetList = list.New()
			packets.lists[reflect.TypeOf(packet)] = packetList
		}
		log.WithField("packet", packetType).Debugln("Add pending packet")
		packetList.PushBack(packet)
		return nil
	}
	return ErrUnsupportedPendingPacketType
}

// RemoveNextPendingPacket removes first in the list pending packet
func (packets *pendingPacketsList) RemoveNextPendingPacket(packet interface{}) error {
	packets.mutex.Lock()
	defer packets.mutex.Unlock()

	switch packet.(type) {
	case *ParsePacket, *BindPacket, *ExecutePacket, *pgproto3.RowDescription, *pgproto3.ParameterDescription, queryPacket:
		packetType := reflect.TypeOf(packet)
		packetList, ok := packets.lists[packetType]
		if !ok {
			return ErrRemoveFromEmptyPendingList
		}
		currentElement := packetList.Front()
		if currentElement == nil {
			return nil
		}
		log.WithField("packet", packetType).Debugln("Remove pending packet")
		packetList.Remove(currentElement)
		return nil
	}
	return ErrUnsupportedPendingPacketType
}

// RemoveAll pending packets of packet's type
func (packets *pendingPacketsList) RemoveAll(packet interface{}) error {
	packets.mutex.Lock()
	defer packets.mutex.Unlock()

	switch packet.(type) {
	case *ParsePacket, *BindPacket, *ExecutePacket, *pgproto3.RowDescription, *pgproto3.ParameterDescription, queryPacket:
		packetList, ok := packets.lists[reflect.TypeOf(packet)]
		if !ok {
			return nil
		}
		log.Debugln("Remove all pending packets")
		packetList.Init()
		return nil
	}
	return ErrUnsupportedPendingPacketType
}

// GetPendingPacket returns next pending packet
func (packets *pendingPacketsList) GetPendingPacket(packet interface{}) (interface{}, error) {
	packets.mutex.RLock()
	defer packets.mutex.RUnlock()

	switch packet.(type) {
	case *ParsePacket, *BindPacket, *ExecutePacket, *pgproto3.RowDescription, *pgproto3.ParameterDescription, queryPacket:
		packetType := reflect.TypeOf(packet)
		packetList, ok := packets.lists[packetType]
		if !ok {
			return nil, nil
		}
		currentElement := packetList.Front()
		if currentElement == nil {
			return nil, nil
		}
		log.WithField("packet", packetType).Debugln("Return pending packet")
		return currentElement.Value, nil
	}
	return nil, ErrUnsupportedPendingPacketType
}

// GetLastPending return last added pending packet
func (packets *pendingPacketsList) GetLastPending(packet interface{}) (interface{}, error) {
	packets.mutex.RLock()
	defer packets.mutex.RUnlock()

	switch packet.(type) {
	case *ParsePacket, *BindPacket, *ExecutePacket, *pgproto3.RowDescription, *pgproto3.ParameterDescription, queryPacket:
		packetType := reflect.TypeOf(packet)
		packetList, ok := packets.lists[packetType]
		if !ok {
			return nil, nil
		}
		currentElement := packetList.Back()
		if currentElement == nil {
			return nil, nil
		}
		log.WithField("packet", packetType).Debugln("Return last added packet")
		return currentElement.Value, nil
	}
	return nil, ErrUnsupportedPendingPacketType
}
