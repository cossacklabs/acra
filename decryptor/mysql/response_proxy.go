package mysql

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/firewall"
	log "github.com/sirupsen/logrus"
)

const (
	// MaxPayloadLen https://dev.mysql.com/doc/internals/en/mysql-packet.html
	// each packet splits into packets of this size
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
const (
	TLS_NONE = iota
	TLS_CLIENT_SWITCH
	TLS_DB_COMPLETE
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
	responseHandler        ResponseHandler
	clientSequenceNumber   int
	serverSequenceNumber   int
	clientProtocol41       bool
	serverProtocol41       bool
	decryptor              base.Decryptor
	firewall               firewall.FirewallInterface
	isTLSHandshake         bool
	dbTLSHandshakeFinished chan bool
	clientConnection       net.Conn
	dbConnection           net.Conn
	tlsConfig              *tls.Config
}

func NewMysqlHandler(decryptor base.Decryptor, dbConnection, clientConnection net.Conn, tlsConfig *tls.Config, firewall firewall.FirewallInterface) (*MysqlHandler, error) {
	return &MysqlHandler{isTLSHandshake: false, dbTLSHandshakeFinished: make(chan bool), decryptor: decryptor, responseHandler: defaultResponseHandler, firewall: firewall, clientConnection: clientConnection, dbConnection: dbConnection, tlsConfig: tlsConfig}, nil
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

func (handler *MysqlHandler) ClientToDbProxy(errCh chan<- error) {
	clientLog := log.WithField("proxy", "client")
	clientLog.Debugln("start proxy client's requests")
	firstPacket := true
	for {
		packet, err := ReadPacket(handler.clientConnection)
		if err != nil {
			log.Debugln("can't read packet from client")
			errCh <- err
			return
		}
		if firstPacket {
			firstPacket = false
			handler.clientProtocol41 = packet.ClientSupportProtocol41()
			if packet.IsSSLRequest() {
				tlsConnection := tls.Server(handler.clientConnection, handler.tlsConfig)
				if err := tlsConnection.Handshake(); err != nil {
					log.WithError(err).Errorln("error in tls handshake with client")
					errCh <- err
					return
				}
				log.Debugln("switched to tls with client. wait switching with db")
				handler.isTLSHandshake = true
				handler.clientConnection = tlsConnection
				if _, err := handler.dbConnection.Write(packet.Dump()); err != nil {
					clientLog.Debugln("can't write send packet to db")
					errCh <- err
					return
				}
				// stop reading and init switching to tls
				handler.dbConnection.SetReadDeadline(time.Now())
				// we should wait when db proxy part will finish handshake to avoid case when new packets from client
				// will be proxied in this function to db before handshake will be completed
				select {
				case <-handler.dbTLSHandshakeFinished:
					log.Debugln("switch to tls complete on client proxy side")
					continue
				case <-time.NewTicker(time.Second).C:
					clientLog.Errorln("timeout on tls handshake with db")
					errCh <- errors.New("handshake timeout")
					return
				}
				continue
			}
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
			handler.clientConnection.Close()
			handler.dbConnection.Close()
			errCh <- io.EOF
			return
		case COM_QUERY:
			sqlQuery := string(data)
			if err := handler.firewall.HandleQuery(sqlQuery); err != nil {
				log.WithError(err).Errorln("error on firewall check")
				errPacket := NewQueryInterruptedError(handler.clientProtocol41)
				packet.SetData(errPacket)
				if _, err := handler.clientConnection.Write(packet.Dump()); err != nil {
					log.WithError(err).Errorln("can't write response with error to client")
				}
				continue
			}
			clientLog.WithField("sql", sqlQuery).Debugln("com_query")
			handler.setQueryHandler(handler.QueryResponseHandler)
			break
		case COM_STMT_PREPARE, COM_STMT_EXECUTE, COM_STMT_CLOSE, COM_STMT_SEND_LONG_DATA, COM_STMT_RESET:
			fallthrough
		default:
			clientLog.Debugf("command %d not supported now", cmd)
		}
		if _, err := handler.dbConnection.Write(inOutput); err != nil {
			clientLog.Debugln("can't write send packet to db")
			errCh <- err
			return
		}
	}
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
	var fieldLogger *log.Entry
	log.Debugln("process fields in text data row")
	for i := range fields {
		fieldLogger = log.WithField("field_index", i)
		value, _, n, err = LengthEncodedString(rowData[pos:])
		if err != nil {
			return nil, err
		}
		if handler.isFieldToDecrypt(fields[i]) {
			decryptedValue, err := handler.decryptor.DecryptBlock(value)
			if err != nil {
				fieldLogger.WithError(err).Errorln("can't decrypt binary data")
			}
			if err == nil && len(decryptedValue) != len(value) {
				fieldLogger.Debugln("update with decrypted value")
				output = append(output, PutLengthEncodedString(decryptedValue)...)
			} else {
				fieldLogger.Debugln("leave value as is")
				output = append(output, rowData[pos:pos+n]...)
			}
			pos += n
			continue
		}
		fieldLogger.Debugln("field is not binary")

		output = append(output, rowData[pos:pos+n]...)
		pos += n
	}
	log.Debugln("finish processing text data row")

	return output, nil
}

func (handler *MysqlHandler) processBinaryDataRow(rowData []byte, fields []*ColumnDescription) ([]byte, error) {
	pos := 0
	var n int
	var err error
	var value []byte
	var output []byte
	for i := range fields {
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
		// https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
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
	handler.decryptor.Reset()
	handler.decryptor.ResetZoneMatch()
	// read fields
	var fields []*ColumnDescription
	var binaryFieldIndexes []int
	// first byte of payload is field count
	// https://dev.mysql.com/doc/internals/en/com-query-response.html#text-resultset
	fieldCount := int(packet.GetData()[0])
	if fieldCount == OK_PACKET || fieldCount == ERR_PACKET {
		log.Debugln("error or empty response packet")
		if _, err := clientConnection.Write(packet.Dump()); err != nil {
			log.WithError(err).Errorln("can't proxy output")
			return err
		}
		return nil
	}
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
	var dataLog *log.Entry
	// read data packets
	for i := 0; ; i++ {
		dataLog = log.WithField("data_row_index", i)
		dataLog.Debugln("read data row")
		fieldDataPacket, err := ReadPacket(dbConnection)
		if err != nil {
			return err
		}
		output = append(output, fieldDataPacket)
		if fieldDataPacket.IsEOF() {
			break
		}

		dataLength := fieldDataPacket.GetPacketPayloadLength()
		dataLog.Debugln("process data row")

		newData, err := handler.processTextDataRow(fieldDataPacket.GetData(), fields)
		if err != nil {
			dataLog.WithError(err).Debugln("can't process text data row")
			return err
		}
		// decrypted data always less than ecrypted
		if len(newData) < dataLength {
			dataLog.WithFields(log.Fields{"oldLength": dataLength, "newLength": len(newData)}).Debugln("update row data")
			fieldDataPacket.SetData(newData)
		}
	}

	// proxy output
	log.Debugln("proxy output")
	for _, dumper := range output {
		if _, err := clientConnection.Write(dumper.Dump()); err != nil {
			log.WithError(err).Errorln("can't proxy output")
			return err
		}
	}
	log.Debugln("query handler finish")
	return nil
}

func (handler *MysqlHandler) DbToClientProxy(errCh chan<- error) {
	serverLog := log.WithField("proxy", "server")
	serverLog.Debugln("start proxy db responses")
	firstPacket := true
	var responseHandler ResponseHandler
	for {
		packet, err := ReadPacket(handler.dbConnection)
		if err != nil {
			if netErr, ok := err.(net.Error); ok {
				if netErr.Timeout() && handler.isTLSHandshake {
					// reset deadline
					handler.dbConnection.SetReadDeadline(time.Time{})
					tlsConnection := tls.Client(handler.dbConnection, handler.tlsConfig)
					if err := tlsConnection.Handshake(); err != nil {
						log.WithError(err).Errorln("error in tls handshake with db")
						errCh <- err
						return
					}
					log.Debugln("switched to tls with db")
					handler.dbConnection = tlsConnection
					handler.dbTLSHandshakeFinished <- true
					continue
				}
			}
			log.Debugln("can't read packet from server")
			errCh <- err
			return
		}
		log.WithField("sequence_number", packet.GetSequenceNumber()).Debugln("new packet from db to client")
		if packet.IsErr() {
			handler.resetQueryHandler()
		}
		if firstPacket {
			firstPacket = false
			handler.serverProtocol41 = packet.ServerSupportProtocol41()
			serverLog.Debugf("set support protocol 41 %v", handler.serverProtocol41)
		}
		responseHandler = handler.getResponseHandler()
		err = responseHandler(packet, handler.dbConnection, handler.clientConnection)
		if err != nil {
			log.WithError(err).Errorln("error in responseHandler")
			errCh <- err
			return
		}

	}
}
