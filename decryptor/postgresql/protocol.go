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
	"github.com/cossacklabs/acra/logging"
)

// PgProtocolState keeps track of PostgreSQL protocol state.
type PgProtocolState struct {
	lastPacketType PacketType
	pendingQuery   base.OnQueryObject
	pendingParse   *ParsePacket
	pendingBind    *BindPacket
	pendingExecute *ExecutePacket
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
	OtherPacket
)

// NewPgProtocolState makes an initial PostgreSQL state, awaiting for queries.
func NewPgProtocolState() *PgProtocolState {
	return &PgProtocolState{lastPacketType: OtherPacket}
}

// LastPacketType returns type of the last seen packet.
func (p *PgProtocolState) LastPacketType() PacketType {
	return p.lastPacketType
}

// PendingQuery returns a query object pending response from the database.
func (p *PgProtocolState) PendingQuery() base.OnQueryObject {
	return p.pendingQuery
}

// PendingParse returns the pending prepared statement, if any.
func (p *PgProtocolState) PendingParse() *ParsePacket {
	return p.pendingParse
}

// PendingBind returns the pending query parameters, if any.
func (p *PgProtocolState) PendingBind() *BindPacket {
	return p.pendingBind
}

// PendingExecute returns the pending query parameters, if any.
func (p *PgProtocolState) PendingExecute() *ExecutePacket {
	return p.pendingExecute
}

// HandleClientPacket observes a packet from client to the database,
// extracts query information from it, and anticipates future database responses.
func (p *PgProtocolState) HandleClientPacket(packet *PacketHandler) error {
	logger := packet.logger

	// Query packets are easy, that's a simple query protocol.
	if packet.IsSimpleQuery() {
		query, err := packet.GetSimpleQuery()
		if err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantExtractQueryString).
				WithError(err).Errorln("Can't fetch query string from Query packet")
			return err
		}
		p.lastPacketType = SimpleQueryPacket
		p.pendingQuery = base.NewOnQueryObjectFromQuery(query)
		return nil
	}

	// Parse packets initiate extended query protocol.
	if packet.IsParse() {
		parsePacket, err := packet.GetParseData()
		if err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantExtractQueryString).
				WithError(err).Errorln("Can't fetch query string from Parse packet")
			return err
		}
		p.lastPacketType = ParseStatementPacket
		p.pendingQuery = base.NewOnQueryObjectFromQuery(parsePacket.QueryString())
		p.pendingParse = parsePacket
		return nil
	}

	// Bind packets carry bound parameters for extended queries.
	if packet.IsBind() {
		bindPacket, err := packet.GetBindData()
		if err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantExtractQueryString).
				WithError(err).Errorln("Can't fetch query parameters from Bind packet")
			return err
		}
		p.lastPacketType = BindStatementPacket
		p.pendingBind = bindPacket
		return nil
	}

	// Execute packets initiate data retrieval from portals.
	if packet.IsExecute() {
		executePacket, err := packet.GetExecuteData()
		if err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantExtractQueryString).
				WithError(err).Errorln("Can't fetch executed query from Execute packet")
			return err
		}
		// There is nothing in the packet to process when we receive it,
		// but we'd like to keep it around while the data responses are flowing.
		p.lastPacketType = OtherPacket
		p.pendingExecute = executePacket
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

	if packet.IsParseComplete() {
		p.lastPacketType = ParseCompletePacket
		return nil
	}

	if packet.IsBindComplete() {
		p.lastPacketType = BindCompletePacket
		return nil
	}

	// ReadyForQuery starts a new query processing. Forget pending queries.
	// There is nothing interesting in the packet otherwise.
	if packet.IsReadyForQuery() {
		p.pendingQuery = nil
		p.pendingParse = nil
		p.pendingBind = nil
		p.pendingExecute = nil
		p.lastPacketType = OtherPacket
		return nil
	}

	// We are not interested in other packets, just pass them through.
	p.lastPacketType = OtherPacket
	return nil
}
