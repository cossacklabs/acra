package mysql

type SqlError struct {
	Code    uint16
	Message string
	State   string
}

const (
	// https://dev.mysql.com/doc/refman/5.5/en/error-messages-server.html#error_er_query_interrupted
	ER_QUERY_INTERRUPTED_CODE  = 1317
	ER_QUERY_INTERRUPTED_STATE = "70100"
)

func newQueryInterruptedError() *SqlError {
	e := new(SqlError)
	e.Code = ER_QUERY_INTERRUPTED_CODE
	e.State = ER_QUERY_INTERRUPTED_STATE
	e.Message = "Query execution was interrupted"
	return e
}

// NewQueryInterruptedError return packed QueryInterrupted error
// https://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html
func NewQueryInterruptedError(isProtocol41 bool) []byte {
	mysqlError := newQueryInterruptedError()
	var data []byte
	if isProtocol41 {
		// 1 byte ERR_PACKET flag + 2 bytes of error code = 3
		data = make([]byte, 0, 3+len(mysqlError.Message))
	} else {
		// 1 byte ERR_PACKET flag + 2 bytes of error code + 6 bytes of state (protocol41) = 9
		data = make([]byte, 0, 9+len(mysqlError.Message))
	}

	data = append(data, ERR_PACKET)
	data = append(data, byte(mysqlError.Code), byte(mysqlError.Code>>8))

	if isProtocol41 {
		data = append(data, '#')
		data = append(data, mysqlError.State...)
	}

	data = append(data, mysqlError.Message...)
	return data
}
