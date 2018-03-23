package mysql

import "fmt"

type SqlError struct {
	Code    uint16
	Message string
	State   string
}

func (e *SqlError) Error() string {
	return fmt.Sprintf("ERROR %d (%s): %s", e.Code, e.State, e.Message)
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

func NewError(isProtocol41 bool) []byte {
	mysqlError := newQueryInterruptedError()
	data := make([]byte, 0, 16+len(mysqlError.Message))

	data = append(data, ERR_PACKET)
	data = append(data, byte(mysqlError.Code), byte(mysqlError.Code>>8))

	if isProtocol41 {
		data = append(data, '#')
		data = append(data, mysqlError.State...)
	}

	data = append(data, mysqlError.Message...)
	return data
}
