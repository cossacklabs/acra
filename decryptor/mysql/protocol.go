package mysql

import "github.com/cossacklabs/acra/decryptor/base"

// ProtocolState keeps track of MySQL protocol state.
type ProtocolState struct {
	pendingParse base.OnQueryObject
}

// NewProtocolState makes an initial MySQL state, awaiting for queries.
func NewProtocolState() *ProtocolState {
	return &ProtocolState{}
}

// PendingParse returns the pending prepared statement, if any.
func (p *ProtocolState) PendingParse() base.OnQueryObject {
	return p.pendingParse
}

// SetPendingParse set pendingParse value
func (p *ProtocolState) SetPendingParse(obj base.OnQueryObject) {
	p.pendingParse = obj
}
