package mysql

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/cossacklabs/acra/acra-censor"
	"github.com/cossacklabs/acra/acra-censor/handlers"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/sirupsen/logrus"
)

const (
	// MaxPayloadLen https://dev.mysql.com/doc/internals/en/mysql-packet.html
	// each packet splits into packets of this size
	MaxPayloadLen                int = 1<<24 - 1
	CLIENT_WAIT_DB_TLS_HANDSHAKE     = 5
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
	isBlob := value >= MYSQL_TYPE_TINY_BLOB && value <= MYSQL_TYPE_BLOB
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
	currentCommand       byte
	// clientDeprecateEOF  if false then expect EOF on response result as terminator otherwise not
	clientDeprecateEOF     bool
	decryptor              base.Decryptor
	acracensor             acracensor.AcraCensorInterface
	isTLSHandshake         bool
	dbTLSHandshakeFinished chan bool
	clientConnection       net.Conn
	dbConnection           net.Conn
	tlsConfig              *tls.Config
	clientId               []byte
	logger                 *logrus.Entry
}

func NewMysqlHandler(clientId []byte, decryptor base.Decryptor, dbConnection, clientConnection net.Conn, tlsConfig *tls.Config, censor acracensor.AcraCensorInterface) (*MysqlHandler, error) {
	return &MysqlHandler{
		isTLSHandshake:         false,
		dbTLSHandshakeFinished: make(chan bool),
		clientDeprecateEOF:     false,
		decryptor:              decryptor,
		responseHandler:        defaultResponseHandler,
		acracensor:             censor,
		clientConnection:       clientConnection,
		dbConnection:           dbConnection,
		tlsConfig:              tlsConfig,
		logger:                 logrus.WithField("client_id", string(clientId))}, nil
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

func (handler *MysqlHandler) ClientToDbConnector(errCh chan<- error) {
	clientLog := handler.logger.WithField("proxy", "client")
	clientLog.Debugln("Start proxy client's requests")
	firstPacket := true
	for {
		packet, err := ReadPacket(handler.clientConnection)
		if err != nil {
			handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorResponseConnectorCantReadFromClient).
				Debugln("Can't read packet from client")
			errCh <- err
			return
		}
		if firstPacket {
			firstPacket = false
			handler.clientProtocol41 = packet.ClientSupportProtocol41()
			handler.clientDeprecateEOF = packet.IsClientDeprecateEOF()
			clientLog = clientLog.WithField("deprecate_eof", handler.clientDeprecateEOF)
			if packet.IsSSLRequest() {
				if handler.tlsConfig == nil {
					handler.logger.Errorln("To support TLS connections you must pass TLS key and certificate for AcraServer that will be used " +
						"for connections AcraServer->Database and CA certificate which will be used to verify certificate " +
						"from database")
					handler.logger.Debugln("Send error to db")
					errPacket := NewQueryInterruptedError(handler.clientProtocol41)
					packet.SetData(errPacket)
					if _, err := handler.clientConnection.Write(packet.Dump()); err != nil {
						handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorResponseConnectorCantWriteToClient).
							Errorln("Can't write response with error to client")
					}
					errCh <- network.ErrEmptyTLSConfig
					return
				}
				tlsConnection := tls.Server(handler.clientConnection, handler.tlsConfig)
				if err := tlsConnection.Handshake(); err != nil {
					handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
						Errorln("Error in tls handshake with client")
					errCh <- err
					return
				}
				handler.logger.Debugln("Switched to tls with client. wait switching with db")
				handler.isTLSHandshake = true
				handler.clientConnection = tlsConnection
				if _, err := handler.dbConnection.Write(packet.Dump()); err != nil {
					clientLog.Debugln("Can't write send packet to db")
					errCh <- err
					return
				}
				// stop reading and init switching to tls
				handler.dbConnection.SetReadDeadline(time.Now())
				// we should wait when db proxy part will finish handshake to avoid case when new packets from client
				// will be proxied in this function to db before handshake will be completed
				select {
				case <-handler.dbTLSHandshakeFinished:
					handler.logger.Debugln("Switch to tls complete on client proxy side")
					continue
				case <-time.NewTicker(time.Second * CLIENT_WAIT_DB_TLS_HANDSHAKE).C:
					clientLog.Errorln("Timeout on tls handshake with db")
					errCh <- errors.New("handshake timeout")
					return
				}
				continue
			}
		}
		handler.clientSequenceNumber = int(packet.GetSequenceNumber())
		clientLog = clientLog.WithField("sequence_number", handler.clientSequenceNumber)
		clientLog.Debugln("New packet")
		inOutput := packet.Dump()
		data := packet.GetData()
		cmd := data[0]
		data = data[1:]
		handler.currentCommand = cmd
		switch cmd {
		case COM_QUIT:
			clientLog.Debugln("Close connections on COM_QUIT command")
			handler.clientConnection.Close()
			handler.dbConnection.Close()
			errCh <- io.EOF
			return
		case COM_QUERY, COM_STMT_EXECUTE:
			query := string(data)
			queryWithHiddenValues, err := handlers.RedactSQLQuery(query)
			if err == handlers.ErrQuerySyntaxError {
				clientLog.WithError(err).Infof("Parsing error on query (first %v symbols): %s", handlers.LogQueryLength, handlers.TrimStringToN(queryWithHiddenValues, handlers.LogQueryLength))
			}
			if err := handler.acracensor.HandleQuery(query); err != nil {
				clientLog.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).Errorln("Error on AcraCensor check")
				errPacket := NewQueryInterruptedError(handler.clientProtocol41)
				packet.SetData(errPacket)
				if _, err := handler.clientConnection.Write(packet.Dump()); err != nil {
					handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorResponseConnectorCantWriteToClient).
						Errorln("Can't write response with error to client")
				}
				continue
			}
			clientLog.WithField("sql", queryWithHiddenValues).Debugln("Com_query")
			handler.setQueryHandler(handler.QueryResponseHandler)
			break
		case COM_STMT_PREPARE, COM_STMT_CLOSE, COM_STMT_SEND_LONG_DATA, COM_STMT_RESET:
			fallthrough
		default:
			clientLog.Debugf("Command %d not supported now", cmd)
		}
		if _, err := handler.dbConnection.Write(inOutput); err != nil {
			clientLog.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorResponseConnectorCantWriteToDB).
				Debugln("Can't write send packet to db")
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
	var fieldLogger *logrus.Entry
	handler.logger.Debugln("Process data rows in text protocol")
	for i := range fields {
		fieldLogger = handler.logger.WithField("field_index", i)
		value, _, n, err = LengthEncodedString(rowData[pos:])
		if err != nil {
			return nil, err
		}
		if handler.isFieldToDecrypt(fields[i]) {
			decryptedValue, err := handler.decryptor.DecryptBlock(value)
			if err != nil {
				fieldLogger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).
					Errorln("Can't decrypt binary data")
			}
			if err == nil && len(decryptedValue) != len(value) {
				fieldLogger.Debugln("Update with decrypted value")
				output = append(output, PutLengthEncodedString(decryptedValue)...)
			} else {
				fieldLogger.Debugln("Leave value as is")
				output = append(output, rowData[pos:pos+n]...)
			}
			pos += n
			continue
		}
		fieldLogger.Debugln("Field is not binary")

		output = append(output, rowData[pos:pos+n]...)
		pos += n
	}
	handler.logger.Debugln("Finish processing text data row")

	return output, nil
}

func (handler *MysqlHandler) processBinaryDataRow(rowData []byte, fields []*ColumnDescription) ([]byte, error) {
	pos := 0
	var n int
	var err error
	var value []byte
	var output []byte

	handler.logger.Debugln("Process data rows in binary protocol")
	// no data in response
	if rowData[0] == EOF_PACKET {
		return rowData, nil
	}

	if rowData[0] != OK_PACKET {
		return nil, ErrMalformPacket
	}

	// https://dev.mysql.com/doc/internals/en/binary-protocol-resultset-row.html
	// 1 - packet header
	// 7 + 2 offset from docs
	pos = 1 + ((len(fields) + 7 + 2) >> 3)
	nullBitmap := rowData[1:pos]
	output = append(output, rowData[:pos]...)

	for i := range fields {
		// https://dev.mysql.com/doc/internals/en/null-bitmap.html
		// (i+2) / 8 -- calculate byte number in bitmap
		// (i + 2) % 8 -- calculate bit number for current field
		if nullBitmap[(i+2)/8]&(1<<(uint(i+2)%8)) > 0 {
			continue
		}
		if handler.isFieldToDecrypt(fields[i]) {
			value, _, n, err = LengthEncodedString(rowData[pos:])
			if err != nil {
				handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).
					Errorln("Can't handle length encoded string binary value")
				return nil, err
			}
			decryptedValue, err := handler.decryptor.DecryptBlock(value)
			if err != nil {
				handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).
					Errorln("Can't decrypt binary data")
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
				handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).
					Errorln("Can't handle length encoded string non binary value")
				return nil, err
			}
			continue
		case MYSQL_TYPE_DATE, MYSQL_TYPE_NEWDATE, MYSQL_TYPE_TIMESTAMP, MYSQL_TYPE_DATETIME, MYSQL_TYPE_TIME:
			_, _, n, err = LengthEncodedInt(rowData[pos:])
			if err != nil {
				return nil, err
			}
			output = append(output, rowData[pos:pos+n]...)
			pos += n
			continue
		default:
			return nil, fmt.Errorf("while decrypting MySQL query found unknown FieldType %d %s", fields[i].Type, fields[i].Name)
		}
	}
	return output, nil
}

func (handler *MysqlHandler) expectEOFOnColumnDefinition() bool {
	return !handler.clientDeprecateEOF
}

func (handler *MysqlHandler) isPreparedStatementResult() bool {
	return handler.currentCommand == COM_STMT_EXECUTE
}

func (handler *MysqlHandler) QueryResponseHandler(packet *MysqlPacket, dbConnection, clientConnection net.Conn) (err error) {
	handler.resetQueryHandler()
	handler.decryptor.Reset()
	handler.decryptor.ResetZoneMatch()
	// read fields
	var fields []*ColumnDescription
	var binaryFieldIndexes []int
	// first byte of payload is field count
	// https://dev.mysql.com/doc/internals/en/com-query-response.html#text-resultset
	fieldCount := int(packet.GetData()[0])
	output := []Dumper{packet}
	if fieldCount != ERR_PACKET && fieldCount > 0 {
		handler.logger.Debugln("Read column descriptions")
		for i := 0; ; i++ {
			handler.logger.WithField("column_index", i).Debugln("Read column description")
			fieldPacket, err := ReadPacket(dbConnection)
			if err != nil {
				handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorResponseConnectorCantProcessColumn).
					Errorln("Can't read packet with column description")
				return err
			}
			output = append(output, fieldPacket)
			if handler.expectEOFOnColumnDefinition() {
				if fieldPacket.IsEOF() {
					if i != fieldCount {
						handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorProtocolProcessing).Errorln("EOF and field count != current row packet count")
						return ErrMalformPacket
					}
					break
				}
			}
			handler.logger.WithField("column_index", i).Debugln("Parse field")
			field, err := ParseResultField(fieldPacket.GetData())
			if err != nil {
				handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorProtocolProcessing).WithError(err).Errorln("Can't parse result field")
				return err
			}
			if field.IsBinary() {
				handler.logger.WithField("column_index", i).Debugln("Binary field")
				binaryFieldIndexes = append(binaryFieldIndexes, i)
			}
			fields = append(fields, field)
			if !handler.expectEOFOnColumnDefinition() && i == (fieldCount-1) {
				break
			}

		}
		handler.logger.Debugln("Read data rows")
		if handler.isPreparedStatementResult() {
			for {
				fieldDataPacket, err := ReadPacket(dbConnection)
				if err != nil {
					handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorProtocolProcessing).WithError(err).Errorln("Can't read data packet")
					return err
				}
				output = append(output, fieldDataPacket)
				if fieldDataPacket.data[0] == EOF_PACKET {
					break
				}
				newData, err := handler.processBinaryDataRow(fieldDataPacket.GetData(), fields)
				if err != nil {
					handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorProtocolProcessing).
						Debugln("Can't process binary data row")
					return err
				}
				dataLength := fieldDataPacket.GetPacketPayloadLength()
				// decrypted data always less than ecrypted
				if len(newData) < dataLength {
					handler.logger.WithFields(logrus.Fields{"oldLength": dataLength, "newLength": len(newData)}).Debugln("Update row data")
					fieldDataPacket.SetData(newData)
				}
			}
		} else {
			var dataLog *logrus.Entry
			// read data packets
			for i := 0; ; i++ {
				dataLog = handler.logger.WithField("data_row_index", i)
				dataLog.Debugln("Read data row")
				fieldDataPacket, err := ReadPacket(dbConnection)
				if err != nil {
					handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorProtocolProcessing).WithError(err).Errorln("Can't read data packet")
					return err
				}
				output = append(output, fieldDataPacket)
				if fieldDataPacket.IsEOF() {
					dataLog.Debugln("Empty result set")
					break
				}
				// skip if no binary fields and nothing to decrypt
				if len(fields) == 0 {
					continue
				}
				dataLog.Debugln("Process data text row")
				newData, err := handler.processTextDataRow(fieldDataPacket.GetData(), fields)
				if err != nil {
					dataLog.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorProtocolProcessing).
						Debugln("Can't process text data row")
					return err
				}
				dataLength := fieldDataPacket.GetPacketPayloadLength()
				// decrypted data always less than ecrypted
				if len(newData) < dataLength {
					dataLog.WithFields(logrus.Fields{"oldLength": dataLength, "newLength": len(newData)}).Debugln("Update row data")
					fieldDataPacket.SetData(newData)
				}

			}
		}

	}

	// proxy output
	handler.logger.Debugln("Proxy output")
	for _, dumper := range output {
		if _, err := clientConnection.Write(dumper.Dump()); err != nil {
			handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorResponseConnectorCantWriteToClient).
				Errorln("Can't proxy output")
			return err
		}
	}
	handler.resetQueryHandler()
	handler.logger.Debugln("Query handler finish")
	return nil
}

func (handler *MysqlHandler) DbToClientConnector(errCh chan<- error) {
	serverLog := handler.logger.WithField("proxy", "server")
	serverLog.Debugln("Start proxy db responses")
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
						handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
							Errorln("Error in tls handshake with db")
						errCh <- err
						return
					}
					handler.logger.Debugln("Switched to tls with db")
					handler.dbConnection = tlsConnection
					handler.dbTLSHandshakeFinished <- true
					continue
				}
			}
			handler.logger.Debugln("Can't read packet from server")
			errCh <- err
			return
		}
		handler.logger.WithField("sequence_number", packet.GetSequenceNumber()).Debugln("New packet from db to client")
		if packet.IsErr() {
			handler.resetQueryHandler()
		}
		if firstPacket {
			firstPacket = false
			handler.serverProtocol41 = packet.ServerSupportProtocol41()
			serverLog.Debugf("Set support protocol 41 %v", handler.serverProtocol41)
		}
		responseHandler = handler.getResponseHandler()
		err = responseHandler(packet, handler.dbConnection, handler.clientConnection)
		if err != nil {
			handler.resetQueryHandler()
			handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorResponseConnectorCantWriteToServer).
				Errorln("Error in responseHandler")
			errCh <- err
			return
		}

	}
}
