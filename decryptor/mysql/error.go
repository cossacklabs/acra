/*
Copyright 2016, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mysql

// SQLError is used for passing SQL errors
type SQLError struct {
	Code    uint16
	Message string
	State   string
}

// Interrupted code constants.
const (
	// https://dev.mysql.com/doc/refman/5.5/en/error-messages-server.html#error_er_query_interrupted
	ErQueryInterruptedCode  = 1317
	ErQueryInterruptedState = "70100"
)

func newQueryInterruptedError() *SQLError {
	e := new(SQLError)
	e.Code = ErQueryInterruptedCode
	e.State = ErQueryInterruptedState
	e.Message = "Query execution was interrupted"
	return e
}

// NewQueryInterruptedError return packed QueryInterrupted error
// https://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html
func NewQueryInterruptedError(isProtocol41 bool) []byte {
	mysqlError := newQueryInterruptedError()
	var data []byte
	if isProtocol41 {
		// 1 byte ErrPacket flag + 2 bytes of error code = 3
		data = make([]byte, 0, 3+len(mysqlError.Message))
	} else {
		// 1 byte ErrPacket flag + 2 bytes of error code + 6 bytes of state (protocol41) = 9
		data = make([]byte, 0, 9+len(mysqlError.Message))
	}

	data = append(data, ErrPacket)
	data = append(data, byte(mysqlError.Code), byte(mysqlError.Code>>8))

	if isProtocol41 {
		data = append(data, '#')
		data = append(data, mysqlError.State...)
	}

	data = append(data, mysqlError.Message...)
	return data
}
