/*
 * Copyright 2020, Cossack Labs Limited
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
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/sqlparser/dependency/querypb"
	log "github.com/sirupsen/logrus"
)

type queryPacket struct {
	preparedStatement *PgPreparedStatement
	bindPacket        *BindPacket
	executePacket     *ExecutePacket
	simpleQueryPacket string
}

func newQueryPacket(query string) queryPacket {
	return queryPacket{simpleQueryPacket: query}
}

func newExtendedQueryPacket(preparedStatement *PgPreparedStatement, bindPacket *BindPacket, executePacket *ExecutePacket) queryPacket {
	return queryPacket{preparedStatement: preparedStatement, bindPacket: bindPacket, executePacket: executePacket}
}

// String return SimpleQuery or Prepared with statement name for log purposes
func (queryPacket queryPacket) String() string {
	if queryPacket.executePacket != nil {
		return "Prepared: " + queryPacket.preparedStatement.name
	}
	return "SimpleQuery"
}

// GetSQLQuery returns SQL query. If packet is SimpleQuery then returns query, otherwise returns query from the Parse packet
func (queryPacket queryPacket) GetSQLQuery() string {
	if queryPacket.executePacket != nil {
		return queryPacket.preparedStatement.QueryText()
	}
	return queryPacket.simpleQueryPacket
}

func (queryPacket queryPacket) zeroize() {
	// clear sensitive data where we can
	queryPacket.simpleQueryPacket = ""
	if queryPacket.executePacket != nil {
		queryPacket.executePacket.Zeroize()
		queryPacket.bindPacket.Zeroize()
		queryPacket.preparedStatement.text = ""
		bv := map[string]*querypb.BindVariable{}
		sqlparser.Normalize(queryPacket.preparedStatement.sql, bv, sqlparser.ValueMask)
	}
}

// PgProtocolState keeps track of PostgreSQL protocol state.
type PgProtocolState struct {
	parser *sqlparser.Parser

	lastPacketType PacketType
	// collect queries from the application that waiting DataRows from the database to correctly map settings of
	// transparent encryption and type awareness to the result rows
	pendingQueryPackets *pendingPacketsList
	registry            base.PreparedStatementRegistry
}

// PacketType describes how to handle a message packet.
type PacketType int

// Possible PacketType values.
const (
	SimpleQueryPacket PacketType = iota
	ParseStatementPacket
	ParseCompletePacket
	BindStatementPacket
	BindCompletePacket
	DataPacket
	RowDescriptionPacket
	ParameterDescriptionPacket
	ReadyForQueryPacket
	ExecutePacketType
	OtherPacket
)

// NewPgProtocolState makes an initial PostgreSQL state, awaiting for queries.
func NewPgProtocolState(parser *sqlparser.Parser, registry base.PreparedStatementRegistry) *PgProtocolState {
	return &PgProtocolState{lastPacketType: OtherPacket, parser: parser,
		pendingQueryPackets: newPendingPacketsList(), registry: registry}
}

// LastPacketType returns type of the last seen packet.
func (p *PgProtocolState) LastPacketType() PacketType {
	return p.lastPacketType
}

// HandleClientPacket observes a packet from client to the database,
// extracts query information from it, and anticipates future database responses.
func (p *PgProtocolState) HandleClientPacket(packet *PacketHandler) error {
	// Query packets are easy, that's a simple query protocol.
	if packet.IsSimpleQuery() {
		p.lastPacketType = SimpleQueryPacket
		return nil
	}

	// Parse packets initiate extended query protocol.
	if packet.IsParse() {
		p.lastPacketType = ParseStatementPacket
		return nil
	}

	// Bind packets carry bound parameters for extended queries.
	if packet.IsBind() {
		p.lastPacketType = BindStatementPacket
		return nil
	}

	// Execute packets initiate data retrieval from portals.
	if packet.IsExecute() {
		p.lastPacketType = ExecutePacketType
		return nil
	}

	// We are not interested in other packets, just pass them through.
	p.lastPacketType = OtherPacket
	return nil
}

// HandleDatabasePacket observes a packet with database response,
// extracts useful information from it, and confirms client requests.
func (p *PgProtocolState) HandleDatabasePacket(packet *PacketHandler) error {
	// This is data response to the previously issued query.
	if packet.IsDataRow() {
		p.lastPacketType = DataPacket
		return nil
	}

	if packet.IsRowDescription() {
		p.lastPacketType = RowDescriptionPacket
		return nil
	}

	if packet.IsParameterDescription() {
		p.lastPacketType = ParameterDescriptionPacket
		return nil
	}

	if packet.IsParseComplete() {
		p.lastPacketType = ParseCompletePacket
		return nil
	}

	if packet.IsBindComplete() {
		p.lastPacketType = BindCompletePacket
		return nil
	}

	if packet.IsCommandComplete() || packet.IsEmptyQueryResponse() || packet.IsPortalSuspended() || packet.IsErrorResponse() {
		p.lastPacketType = OtherPacket
		pendingQueryPacket, err := p.pendingQueryPackets.GetPendingPacket(queryPacket{})
		if err != nil {
			log.WithError(err).Errorln("No pending qury packet")
			return err
		}
		// valid case if received ErrorResponse for non-query packets from the database
		if pendingQueryPacket == nil {
			if !packet.IsErrorResponse() {
				log.Warningln("Can't find pending query packet")
			}
			return nil
		}
		log.WithField("command", pendingQueryPacket.(queryPacket)).Infoln("Command complete")
		if err := p.pendingQueryPackets.RemoveNextPendingPacket(queryPacket{}); err != nil {
			return err
		}
		return nil
	}

	// ReadyForQuery starts a new query processing. Forget pending queries.
	// There is nothing interesting in the packet otherwise.
	if packet.IsReadyForQuery() {
		p.lastPacketType = ReadyForQueryPacket
		return nil
	}

	// We are not interested in other packets, just pass them through.
	p.lastPacketType = OtherPacket
	return nil
}
