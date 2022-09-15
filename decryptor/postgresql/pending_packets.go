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
	"github.com/jackc/pgx/pgproto3"
	"reflect"
)

type pendingPacketsList struct {
	lists map[reflect.Type]*list.List
}

func newPendingPacketsList() *pendingPacketsList {
	return &pendingPacketsList{lists: make(map[reflect.Type]*list.List)}
}

var ErrUnsupportedPendingPacketType = errors.New("unsupported pending packet type")
var ErrRemoveFromEmptyPendingList = errors.New("removing from empty pending list")

// Add packet to pending list of packets of this type
func (packets *pendingPacketsList) Add(packet interface{}) error {
	switch packet.(type) {
	case *ParsePacket, *BindPacket, *ExecutePacket, *pgproto3.RowDescription, *pgproto3.ParameterDescription:
		packetList, ok := packets.lists[reflect.TypeOf(packet)]
		if !ok {
			packetList = list.New()
			packets.lists[reflect.TypeOf(packet)] = packetList
		}
		packetList.PushBack(packet)
		return nil
	}
	return ErrUnsupportedPendingPacketType
}

// Remove packet from list of pending packets only if it is current pending packet
func (packets *pendingPacketsList) Remove(packet interface{}) error {
	switch packet.(type) {
	case *ParsePacket, *BindPacket, *ExecutePacket, *pgproto3.RowDescription, *pgproto3.ParameterDescription:
		packetList, ok := packets.lists[reflect.TypeOf(packet)]
		if !ok {
			return ErrRemoveFromEmptyPendingList
		}
		currentElement := packetList.Front()
		if currentElement.Value != packet {
			return errors.New("removing not current packet")
		}
		packetList.Remove(currentElement)
		return nil
	}
	return ErrUnsupportedPendingPacketType
}

// RemoveCurrent removes first in the list pending packet
func (packets *pendingPacketsList) RemoveCurrent(packet interface{}) error {
	switch packet.(type) {
	case *ParsePacket, *BindPacket, *ExecutePacket, *pgproto3.RowDescription, *pgproto3.ParameterDescription:
		packetList, ok := packets.lists[reflect.TypeOf(packet)]
		if !ok {
			return ErrRemoveFromEmptyPendingList
		}
		currentElement := packetList.Front()
		packetList.Remove(currentElement)
		return nil
	}
	return ErrUnsupportedPendingPacketType
}

// RemoveAll pending packets of packet's type
func (packets *pendingPacketsList) RemoveAll(packet interface{}) error {
	switch packet.(type) {
	case *ParsePacket, *BindPacket, *ExecutePacket, *pgproto3.RowDescription, *pgproto3.ParameterDescription:
		packetList, ok := packets.lists[reflect.TypeOf(packet)]
		if !ok {
			return nil
		}
		packetList.Init()
		return nil
	}
	return ErrUnsupportedPendingPacketType
}

func (packets *pendingPacketsList) GetPendingPacket(packet interface{}) (interface{}, error) {
	switch packet.(type) {
	case *ParsePacket, *BindPacket, *ExecutePacket, *pgproto3.RowDescription, *pgproto3.ParameterDescription:
		packetList, ok := packets.lists[reflect.TypeOf(packet)]
		if !ok {
			return nil, nil
		}
		currentElement := packetList.Front()
		return currentElement.Value, nil
	}
	return nil, ErrUnsupportedPendingPacketType
}
