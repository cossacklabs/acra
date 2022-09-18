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
	"github.com/cossacklabs/acra/sqlparser"
)

// PgProtocolState keeps track of PostgreSQL protocol state.
type PgProtocolState struct {
	parser *sqlparser.Parser

	lastPacketType PacketType
	// some packets have pairs request/response and we save data from request only after receiving successful response
	// here we save requests that wait acceptance by database
	pendingPackets *pendingPacketsList
	pendingQuery   base.OnQueryObject
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
	OtherPacket
)

// NewPgProtocolState makes an initial PostgreSQL state, awaiting for queries.
func NewPgProtocolState(parser *sqlparser.Parser) *PgProtocolState {
	return &PgProtocolState{lastPacketType: OtherPacket, parser: parser, pendingPackets: newPendingPacketsList()}
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
func (p *PgProtocolState) PendingParse() (*ParsePacket, error) {
	packet, err := p.pendingPackets.GetPendingPacket(&ParsePacket{})
	if err != nil {
		return nil, err
	}
	if packet == nil {
		return nil, nil
	}
	return packet.(*ParsePacket), nil
}

// LastParse returns the last added ParsePacket
func (p *PgProtocolState) LastParse() (*ParsePacket, error) {
	packet, err := p.pendingPackets.GetLast(&ParsePacket{})
	if err != nil {
		return nil, err
	}
	if packet == nil {
		return nil, nil
	}
	return packet.(*ParsePacket), nil
}

// PendingBind returns the pending query parameters, if any.
func (p *PgProtocolState) PendingBind() (*BindPacket, error) {
	packet, err := p.pendingPackets.GetPendingPacket(&BindPacket{})
	if err != nil {
		return nil, err
	}
	if packet == nil {
		return nil, nil
	}
	return packet.(*BindPacket), nil
}

// LastBind returns the last added BindPacket
func (p *PgProtocolState) LastBind() (*BindPacket, error) {
	packet, err := p.pendingPackets.GetLast(&BindPacket{})
	if err != nil {
		return nil, err
	}
	if packet == nil {
		return nil, nil
	}
	return packet.(*BindPacket), nil
}

// PendingExecute returns the pending query parameters, if any.
func (p *PgProtocolState) PendingExecute() (*ExecutePacket, error) {
	packet, err := p.pendingPackets.GetPendingPacket(&ExecutePacket{})
	if err != nil {
		return nil, err
	}
	if packet == nil {
		return nil, nil
	}
	return packet.(*ExecutePacket), nil
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
		p.pendingQuery = base.NewOnQueryObjectFromQuery(query, p.parser)
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
		p.pendingQuery = base.NewOnQueryObjectFromQuery(parsePacket.QueryString(), p.parser)
		if err := p.pendingPackets.Add(parsePacket); err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantExtractQueryString).
				WithError(err).Errorln("Can't save parse packet")
			return err
		}
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
		if err := p.pendingPackets.Add(bindPacket); err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantExtractQueryString).
				WithError(err).Errorln("Can't save pending Bind packet")
			return err
		}
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
		if err := p.pendingPackets.Add(executePacket); err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantExtractQueryString).
				WithError(err).Errorln("Can't save pending Execute packet")
			return err
		}
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

	// ReadyForQuery starts a new query processing. Forget pending queries.
	// There is nothing interesting in the packet otherwise.
	if packet.IsReadyForQuery() {
		if err := p.forgetPendingExecute(); err != nil {
			return err
		}
		p.forgetPendingQuery()

		// Sensitive data in this bind was already cleared after processing BindComplete packet,
		// so here we only set it to `nil`
		if err := p.forgetPendingBind(); err != nil {
			return err
		}

		p.lastPacketType = ReadyForQueryPacket
		return nil
	}

	// We are not interested in other packets, just pass them through.
	p.lastPacketType = OtherPacket
	return nil
}

func (p *PgProtocolState) forgetPendingParse() error {
	// We forget sensitive data here, but not the bind itself
	// because it's needed in handleQueryDataPacket(),
	// then we set `pendingBind` to `nil` after receiving ReadyForQuery
	pendingParse, err := p.pendingPackets.GetPendingPacket(&ParsePacket{})
	if err != nil {
		return err
	}
	if pendingParse != nil {
		pendingParse.(*ParsePacket).Zeroize()
		if err := p.pendingPackets.RemoveCurrent(pendingParse.(*ParsePacket)); err != nil {
			return err
		}
	}
	return nil
}

func (p *PgProtocolState) forgetPendingBind() error {
	// We forget sensitive data here, but not the bind itself
	// because it's needed in handleQueryDataPacket(),
	// then we set `pendingBind` to `nil` after receiving ReadyForQuery
	pendingBind, err := p.pendingPackets.GetPendingPacket(&BindPacket{})
	if err != nil {
		return err
	}
	if pendingBind != nil {
		pendingBind.(*BindPacket).Zeroize()
		if err := p.pendingPackets.RemoveCurrent(pendingBind.(*BindPacket)); err != nil {
			return err
		}
	}
	return nil
}

func (p *PgProtocolState) zeroizePendingBind() error {
	// We forget sensitive data here, but not the bind itself
	// because it's needed in handleQueryDataPacket(),
	// then we set `pendingBind` to `nil` after receiving ReadyForQuery
	pendingBind, err := p.pendingPackets.GetPendingPacket(&BindPacket{})
	if err != nil {
		return err
	}
	if pendingBind != nil {
		pendingBind.(*BindPacket).Zeroize()
	}
	return nil
}

func (p *PgProtocolState) forgetPendingExecute() error {
	pendingPacket, err := p.pendingPackets.GetPendingPacket(&ExecutePacket{})
	if err != nil {
		return err
	}
	if pendingPacket != nil {
		pendingPacket.(*ExecutePacket).Zeroize()
		if err := p.pendingPackets.RemoveCurrent(pendingPacket.(*ExecutePacket)); err != nil {
			return err
		}
	}
	return nil
}

func (p *PgProtocolState) forgetPendingQuery() {
	// OnQuery uses "string" values and those can't be safely zeroized :(
	p.pendingQuery = nil
}
