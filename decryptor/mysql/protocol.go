package mysql

import "github.com/cossacklabs/acra/decryptor/base"

// ProtocolState keeps track of MySQL protocol state.
type ProtocolState struct {
	pendingParse base.OnQueryObject
	stmtID       uint32
	fields       []*ColumnDescription
}

// NewProtocolState makes an initial MySQL state, awaiting for queries.
func NewProtocolState() *ProtocolState {
	return &ProtocolState{
		fields: make([]*ColumnDescription, 0),
	}
}

// PendingParse returns the pending prepared statement, if any.
func (p *ProtocolState) PendingParse() base.OnQueryObject {
	return p.pendingParse
}

// SetPendingParse set pendingParse value
func (p *ProtocolState) SetPendingParse(obj base.OnQueryObject) {
	p.pendingParse = obj
}

// SetStmtID set stmtID value
func (p *ProtocolState) SetStmtID(id uint32) {
	p.stmtID = id
}

// GetStmtID set stmtID value
func (p *ProtocolState) GetStmtID() uint32 {
	return p.stmtID
}

// AddColumnDescription add ColumnDescription
func (p *ProtocolState) AddColumnDescription(field *ColumnDescription) {
	p.fields = append(p.fields, field)
}
