package mysql

import (
	"bytes"
	"fmt"
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
	MYSQL_TYPE_DECIMAL byte = iota
	MYSQL_TYPE_TINY
	MYSQL_TYPE_SHORT
	MYSQL_TYPE_LONG
	MYSQL_TYPE_FLOAT
	MYSQL_TYPE_DOUBLE
	MYSQL_TYPE_NULL
	MYSQL_TYPE_TIMESTAMP
	MYSQL_TYPE_LONGLONG
	MYSQL_TYPE_INT24
	MYSQL_TYPE_DATE
	MYSQL_TYPE_TIME
	MYSQL_TYPE_DATETIME
	MYSQL_TYPE_YEAR
	MYSQL_TYPE_NEWDATE
	MYSQL_TYPE_VARCHAR
	MYSQL_TYPE_BIT
)

const (
	MYSQL_TYPE_NEWDECIMAL byte = iota + 0xf6
	MYSQL_TYPE_ENUM
	MYSQL_TYPE_SET
	MYSQL_TYPE_TINY_BLOB
	MYSQL_TYPE_MEDIUM_BLOB
	MYSQL_TYPE_LONG_BLOB
	MYSQL_TYPE_BLOB
	MYSQL_TYPE_VAR_STRING
	MYSQL_TYPE_STRING
	MYSQL_TYPE_GEOMETRY
)

const (
	NOT_NULL_FLAG       = 1
	PRI_KEY_FLAG        = 2
	UNIQUE_KEY_FLAG     = 4
	BLOB_FLAG           = 16
	UNSIGNED_FLAG       = 32
	ZEROFILL_FLAG       = 64
	BINARY_FLAG         = 128
	ENUM_FLAG           = 256
	AUTO_INCREMENT_FLAG = 512
	TIMESTAMP_FLAG      = 1024
	SET_FLAG            = 2048
	NUM_FLAG            = 32768
	PART_KEY_FLAG       = 16384
	GROUP_FLAG          = 32768
	UNIQUE_FLAG         = 65536
)

func IsBinaryColumn(value byte) bool {
	isBlob := value > MYSQL_TYPE_TINY_BLOB && value < MYSQL_TYPE_BLOB
	isString := value == MYSQL_TYPE_VAR_STRING || value == MYSQL_TYPE_STRING
	return isString || isBlob || value == MYSQL_TYPE_VARCHAR
}

type ResponseHandler func(packet *MysqlPacket, dbConnection, clientConnection net.Conn) error

func defaultResponseHandler(packet *MysqlPacket, dbConnection, clientConnection net.Conn) error {
	if _, err := clientConnection.Write(packet.Dump()); err != nil {
		return err
	}
	return nil
}

type MysqlHandler struct {
	responseHandler      ResponseHandler
	clientSequenceNumber int
	serverSequenceNumber int
	clientProtocol41     bool
	serverProtocol41     bool
	decryptor            base.Decryptor
}

func NewMysqlHandler(decryptor base.Decryptor) (*MysqlHandler, error) {
	return &MysqlHandler{decryptor: decryptor, responseHandler: defaultResponseHandler}, nil
}

func (handler *MysqlHandler) setQueryHandler(callback ResponseHandler) {
	handler.responseHandler = callback
}
func (handler *MysqlHandler) resetQueryHandler() {
	handler.responseHandler = defaultResponseHandler
}

func (handler *MysqlHandler) getResponseHandler() ResponseHandler {
	return handler.responseHandler
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
			sqlQuery := string(data)
			clientLog.WithField("sql", sqlQuery).Debugln("com_query")
			handler.setQueryHandler(handler.QueryResponseHandler)
			break
		case COM_STMT_PREPARE, COM_STMT_EXECUTE, COM_STMT_CLOSE, COM_STMT_SEND_LONG_DATA, COM_STMT_RESET:
			fallthrough
		default:
			clientLog.Debugf("command %d not supported now", cmd)
		}
		if _, err := dbConnection.Write(inOutput); err != nil {
			clientLog.Debugln("can't write send packet to db")
			errCh <- err
			return
		}
	}
}

type Decryptor interface {
	Decrypt(data []byte) ([]byte, bool, error)
}

type SimpleDecryptor struct{}

func (decryptor *SimpleDecryptor) Decrypt(data []byte) ([]byte, bool, error) {
	if bytes.Equal(data, []byte("test data 1")) {
		return []byte("replaced"), true, nil
	}
	return data, false, nil
}

func (handler *MysqlHandler) isFieldToDecrypt(field *ColumnDescription) bool {
	switch field.Type {
	case MYSQL_TYPE_VARCHAR, MYSQL_TYPE_TINY_BLOB, MYSQL_TYPE_MEDIUM_BLOB, MYSQL_TYPE_LONG_BLOB, MYSQL_TYPE_BLOB,
		MYSQL_TYPE_VAR_STRING, MYSQL_TYPE_STRING:
		return true
	default:
		return false
	}
}

func (handler *MysqlHandler) processTextDataRow(rowData []byte, fields []*ColumnDescription) ([]byte, error) {
	var err error
	var value []byte
	var pos int = 0
	var n int = 0
	var output []byte

	for i := range fields {
		value, _, n, err = LengthEncodedString(rowData[pos:])
		if err != nil {
			return nil, err
		}
		if handler.isFieldToDecrypt(fields[i]) {
			decryptedValue, err := handler.decryptor.DecryptBlock(value)
			if err != nil {
				log.WithError(err).Errorln("can't decrypt binary data")
				return nil, err
			}
			if len(decryptedValue) != len(value) {
				output = append(output, PutLengthEncodedString(decryptedValue)...)
			} else {
				output = append(output, rowData[pos:pos+n]...)
			}
			pos += n
			continue
		}

		output = append(output, rowData[pos:pos+n]...)
		pos += n
	}

	return output, nil
}

func (handler *MysqlHandler) processBinaryDataRow(rowData []byte, fields []*ColumnDescription) ([]byte, error) {
	//if rowData[0] != OK_PACKET {
	//	return nil, ErrMalformPacket
	//}

	//pos := 1 + ((len(fields) + 7 + 2) >> 3)
	//nullBitmap := rowData[1:pos]
	pos := 0
	var n int
	var err error
	var value []byte
	var output []byte
	for i := range fields {
		//if nullBitmap[(i+2)/8]&(1<<(uint(i+2)%8)) > 0 {
		//	continue
		//}
		if handler.isFieldToDecrypt(fields[i]) {
			value, _, n, err = LengthEncodedString(rowData[pos:])
			if err != nil {
				log.WithError(err).Errorln("can't handle length encoded string binary value")
				return nil, err
			}
			decryptedValue, err := handler.decryptor.DecryptBlock(value)
			if err != nil {
				log.WithError(err).Errorln("can't decrypt binary data")
				return nil, err
			}
			if len(value) != len(decryptedValue) {
				output = append(output, PutLengthEncodedString(decryptedValue)...)
			} else {
				output = append(output, rowData[pos:pos+n]...)
			}

			pos += n
			continue
		}

		switch fields[i].Type {
		case MYSQL_TYPE_NULL:
			continue

		case MYSQL_TYPE_TINY:
			output = append(output, rowData[pos])
			pos++
			continue

		case MYSQL_TYPE_SHORT, MYSQL_TYPE_YEAR:
			output = append(output, rowData[pos:pos+2]...)
			pos += 2
			continue

		case MYSQL_TYPE_INT24, MYSQL_TYPE_LONG:
			output = append(output, rowData[pos:pos+4]...)
			pos += 4
			continue

		case MYSQL_TYPE_LONGLONG:
			output = append(output, rowData[pos:pos+8]...)
			pos += 8
			continue

		case MYSQL_TYPE_FLOAT:
			output = append(output, rowData[pos:pos+4]...)
			pos += 4
			continue

		case MYSQL_TYPE_DOUBLE:
			output = append(output, rowData[pos:pos+8]...)
			pos += 8
			continue

		case MYSQL_TYPE_DECIMAL, MYSQL_TYPE_NEWDECIMAL,
			MYSQL_TYPE_BIT, MYSQL_TYPE_ENUM, MYSQL_TYPE_SET, MYSQL_TYPE_GEOMETRY:
			value, _, n, err = LengthEncodedString(rowData[pos:])
			output = append(output, rowData[pos:pos+n]...)
			pos += n
			if err != nil {
				log.WithError(err).Errorln("can't handle length encoded string non binary value")
				return nil, err
			}
			continue
		case MYSQL_TYPE_DATE, MYSQL_TYPE_NEWDATE, MYSQL_TYPE_TIMESTAMP, MYSQL_TYPE_DATETIME, MYSQL_TYPE_TIME:
			_, _, n = LengthEncodedInt(rowData[pos:])
			output = append(output, rowData[pos:pos+n]...)
			pos += n
			continue
		default:
			return nil, fmt.Errorf("Stmt Unknown FieldType %d %s", fields[i].Type, fields[i].Name)
		}
	}
	return output, nil
}

func (handler *MysqlHandler) QueryResponseHandler(packet *MysqlPacket, dbConnection, clientConnection net.Conn) (err error) {
	log.Debugln("query handler")
	handler.resetQueryHandler()
	// read fields
	var fields []*ColumnDescription
	var binaryFieldIndexes []int
	fieldCount := int(packet.GetData()[0])
	output := []Dumper{packet}
	log.Debugln("read column descriptions")
	for i := 0; ; i++ {
		log.WithField("column_index", i).Debugln("read column description")
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
		log.WithField("column_index", i).Debugln("parse field")
		field, err := ParseResultField(fieldPacket.GetData())
		if err != nil {
			return err
		}
		if field.IsBinary() {
			binaryFieldIndexes = append(binaryFieldIndexes, i)
		}
		fields = append(fields, field)
	}

	log.Debugln("read data rows")
	// read data packets
	for i := 0; ; i++ {
		log.WithField("data_row_index", i).Debugln("read data row")
		fieldDataPacket, err := ReadPacket(dbConnection)
		if err != nil {
			return err
		}
		output = append(output, fieldDataPacket)
		if fieldDataPacket.IsEOF() {
			break
		}

		dataLength := fieldDataPacket.GetPacketPayloadLength()
		log.WithField("data_row_index", i).Debugln("process data row")

		newData, err := handler.processTextDataRow(fieldDataPacket.GetData(), fields)
		if err != nil {
			return err
		}
		// decrypted data always less than ecrypted
		if len(newData) < dataLength {
			log.WithFields(log.Fields{"oldLength": dataLength, "newLength": len(newData)}).Debugln("update row data")
			fieldDataPacket.SetData(newData)
		}
	}

	// proxy output
	for _, dumper := range output {
		if _, err := clientConnection.Write(dumper.Dump()); err != nil {
			log.WithError(err).Errorln("can't proxy output")
			return err
		}
	}
	log.Debugln("query handler finish")
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
			handler.resetQueryHandler()
		} else {
			if firstPacket {
				firstPacket = false
				handler.serverProtocol41 = packet.SupportProtocol41()
				serverLog.Debugf("set support protocol 41 %v", handler.serverProtocol41)
			}
			responseHandler = handler.getResponseHandler()
			err := responseHandler(packet, dbConnection, clientConnection)
			if err != nil {
				log.Errorln("error in responseHandler")
				errCh <- err
				return
			}
		}
	}
}
