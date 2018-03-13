package mysql

import (
	"io"
	"net"

	"github.com/cossacklabs/acra/decryptor/base"
	log "github.com/sirupsen/logrus"
)

const (
	MaxPayloadLen int = 1<<24 - 1
)

const (
	COM_SLEEP byte = iota
	COM_QUIT
	COM_INIT_DB
	COM_QUERY
	COM_FIELD_LIST
	COM_CREATE_DB
	COM_DROP_DB
	COM_REFRESH
	COM_SHUTDOWN
	COM_STATISTICS
	COM_PROCESS_INFO
	COM_CONNECT
	COM_PROCESS_KILL
	COM_DEBUG
	COM_PING
	COM_TIME
	COM_DELAYED_INSERT
	COM_CHANGE_USER
	COM_BINLOG_DUMP
	COM_TABLE_DUMP
	COM_CONNECT_OUT
	COM_REGISTER_SLAVE
	COM_STMT_PREPARE
	COM_STMT_EXECUTE
	COM_STMT_SEND_LONG_DATA
	COM_STMT_CLOSE
	COM_STMT_RESET
	COM_SET_OPTION
	COM_STMT_FETCH
	COM_DAEMON
	COM_BINLOG_DUMP_GTID
	COM_RESET_CONNECTION
)

// Binary ColumnTypes https://dev.mysql.com/doc/internals/en/com-query-response.html#column-type
const (
	MYSQL_TYPE_VARCHAR     = 0x0f
	MYSQL_TYPE_TINY_BLOB   = 0xf9
	MYSQL_TYPE_MEDIUM_BLOB = 0xfa
	MYSQL_TYPE_LONG_BLOB   = 0xfb
	MYSQL_TYPE_BLOB        = 0xfc
	MYSQL_TYPE_VAR_STRING  = 0xfd
	MYSQL_TYPE_STRING      = 0xfe
)

func IsBinaryColumn(value int) bool {
	isBlob := value > MYSQL_TYPE_TINY_BLOB && value < MYSQL_TYPE_BLOB
	isString := value == MYSQL_TYPE_VAR_STRING || value == MYSQL_TYPE_STRING
	return isString || isBlob || value == MYSQL_TYPE_VARCHAR
}

type ResponseHandler func(packet *MysqlPacket, dbConnection, clientConnection net.Conn) error

type MysqlHandler struct {
	responseHandlers     []ResponseHandler
	clientSequenceNumber int
	serverSequenceNumber int
	clientProtocol41     bool
	serverProtocol41     bool
}

func (handler *MysqlHandler) addQueryHandler(callback ResponseHandler) {
	handler.responseHandlers = append(handler.responseHandlers, callback)
}
func (handler *MysqlHandler) resetQueryHandlers() {
	handler.responseHandlers = handler.responseHandlers[:0]
}

func (handler *MysqlHandler) getResponseHandler() ResponseHandler {
	if len(handler.responseHandlers) > 0 {
		return handler.responseHandlers[0]
	}
	return nil
}

func (handler *MysqlHandler) ClientToDbProxy(decryptor base.Decryptor, dbConnection, clientConnection net.Conn, errCh chan<- error) {
	clientLog := log.WithField("proxy", "client")
	clientLog.Debugln("start proxy client's requests")
	firstPacket := true
	for {
		packet, err := ReadPacket(clientConnection)
		if err != nil {
			log.Debugln("can't read packet from client")
			errCh <- err
			return
		}
		if firstPacket {
			firstPacket = false
			handler.clientProtocol41 = packet.SupportProtocol41()
			clientLog.Debugf("set support protocol 41 %v", handler.clientProtocol41)
		}
		handler.clientSequenceNumber = int(packet.GetSequenceNumber())
		clientLog = clientLog.WithField("sequence_number", handler.clientSequenceNumber)
		clientLog.Debugln("new packet")
		inOutput := packet.Dump()
		data := packet.GetData()
		cmd := data[0]
		data = data[1:]

		switch cmd {
		case COM_QUIT:
			clientLog.Debugln("close connections on COM_QUIT command")
			clientConnection.Close()
			dbConnection.Close()
			errCh <- io.EOF
			return
		case COM_QUERY:
			clientLog.Debugln("com_query")
			handler.addQueryHandler(handler.QueryResponseHandler)
			fallthrough
		case COM_STMT_PREPARE, COM_STMT_EXECUTE, COM_STMT_CLOSE, COM_STMT_SEND_LONG_DATA, COM_STMT_RESET:
			fallthrough
		default:
			clientLog.Debugf("command %d not supported now", cmd)
			if _, err := dbConnection.Write(inOutput); err != nil {
				clientLog.Debugln("can't write send packet to db")
				errCh <- err
				return
			}
		}
	}
}

func (handler *MysqlHandler) QueryResponseHandler(packet *MysqlPacket, dbConnection, clientConnection net.Conn) (err error) {
	log.Debugln("query handler")
	handler.resetQueryHandlers()
	// read fields
	var fields []*ColumnDescription
	var binaryFieldIndexes []int
	fieldCount := int(packet.GetData()[0])
	output := []Dumper{packet}
	for i := 0; ; i++ {
		fieldPacket, err := ReadPacket(dbConnection)
		if err != nil {
			log.WithError(err).Errorln("can't read packet with column description")
			return err
		}
		output = append(output, fieldPacket)
		if fieldPacket.IsEOF() {
			if i != fieldCount {
				return ErrMalformPacket
			}
			break
		}
		field, err := ParseResultField(fieldPacket.GetData())
		if err != nil {
			return err
		}
		if field.IsBinary() {
			binaryFieldIndexes = append(binaryFieldIndexes, i)
		}
		fields = append(fields, field)
	}

	var fieldDatas [][]byte
	// read data packets
	for i := 0; ; i++ {
		fieldDataPacket, err := ReadPacket(dbConnection)
		if err != nil {
			return err
		}
		output = append(output, fieldDataPacket)
		if fieldDataPacket.IsEOF() {
			break
		}
		fieldDatas = append(fieldDatas, fieldDataPacket.GetData())
	}
	for _, index := range binaryFieldIndexes {
		log.Debugf("field with index <%v> has binary data", index)
	}

	// proxy output
	for _, dumper := range output {
		if _, err := clientConnection.Write(dumper.Dump()); err != nil {
			log.WithError(err).Errorln("can't proxy output")
			return err
		}
	}
	return nil
}

func (handler *MysqlHandler) DbToClientProxy(decryptor base.Decryptor, dbConnection, clientConnection net.Conn, errCh chan<- error) {
	serverLog := log.WithField("proxy", "server")
	serverLog.Debugln("start proxy db responses")
	firstPacket := true
	var responseHandler ResponseHandler
	for {
		packet, err := ReadPacket(dbConnection)
		if err != nil {
			log.Debugln("can't read packet from server")
			errCh <- err
			return
		}
		if packet.IsErr() {
			handler.resetQueryHandlers()
		} else {
			responseHandler = handler.getResponseHandler()
			if responseHandler != nil {
				err := responseHandler(packet, dbConnection, clientConnection)
				if err != nil {
					errCh <- err
					return
				}
				continue
			}
			if firstPacket {
				firstPacket = false
				handler.serverProtocol41 = packet.SupportProtocol41()
				serverLog.Debugf("set support protocol 41 %v", handler.serverProtocol41)
			}
		}
		handler.serverSequenceNumber = int(packet.GetSequenceNumber())
		serverLog = serverLog.WithField("sequence_number", handler.serverSequenceNumber)
		serverLog.Debugln("new packet")
		inOutput := packet.Dump()
		if _, err := clientConnection.Write(inOutput); err != nil {
			serverLog.Debugln("can't write send packet to client")
			errCh <- err
			return
		}
	}
}
