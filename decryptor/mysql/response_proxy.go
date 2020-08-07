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

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"go.opencensus.io/trace"
	"io"
	"net"
	"time"

	"github.com/cossacklabs/acra/acra-censor"
	"github.com/cossacklabs/acra/acra-censor/common"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

const (
	// MaxPayloadLen https://dev.mysql.com/doc/internals/en/mysql-packet.html
	// each packet splits into packets of this size
	MaxPayloadLen int = 1<<24 - 1

	// ClientWaitDbTLSHandshake shows max time to wait for database TLS handshake
	ClientWaitDbTLSHandshake = 5
)

// Possible commands
// comment unused to avoid linter's warnings abous unused constant but leave correct order to re-use it in a future
const (
	_ byte = iota // CommandSleep
	CommandQuit
	_ // CommandInitDB
	CommandQuery
	_ // CommandFieldList
	_ // CommandCreateDB
	_ // CommandDropDB
	_ // CommandRefresh
	_ // CommandShutdown
	_ // CommandStatistics
	_ // CommandProcessInfo
	_ // CommandConnect
	_ // CommandProcessKill
	_ // CommandDebug
	_ // CommandPing
	_ // CommandTime
	_ // CommandDelayedInsert
	_ // CommandChangeUser
	_ // CommandBinLogDump
	_ // CommandTableDump
	_ // CommandConnectOut
	_ // CommandRegisterSlave
	CommandStatementPrepare
	CommandStatementExecute
	CommandStatementSendLongData
	CommandStatementClose
	CommandStatementReset
	_ // CommandSetOption
	_ // CommandStatementFetch
	_ // CommandDaemon
	_ // CommandBinLogDumpGTID
	_ // CommandResetConnection
)

// Binary ColumnTypes https://dev.mysql.com/doc/internals/en/com-query-response.html#column-type
const (
	TypeDecimal byte = iota
	TypeTiny
	TypeShort
	TypeLong
	TypeFloat
	TypeDouble
	TypeNull
	TypeTimestamp
	TypeLongLong
	TypeInt24
	TypeDate
	TypeTime
	TypeDatetime
	TypeYear
	TypeNewDate
	TypeVarchar
	TypeBit
)

// MySQL types
const (
	TypeNewDecimal byte = iota + 0xf6
	TypeEnum
	TypeSet
	TypeTinyBlob
	TypeMediumBlob
	TypeLongBlob
	TypeBlob
	TypeVarString
	TypeString
	TypeGeometry
)

// IsBinaryColumn returns if column is binary data
func IsBinaryColumn(value byte) bool {
	isBlob := value >= TypeTinyBlob && value <= TypeBlob
	isString := value == TypeVarString || value == TypeString
	return isString || isBlob || value == TypeVarchar
}

// ResponseHandler database response header
type ResponseHandler func(ctx context.Context, packet *Packet, dbConnection, clientConnection net.Conn) error

func defaultResponseHandler(ctx context.Context, packet *Packet, _, clientConnection net.Conn) error {
	if _, err := clientConnection.Write(packet.Dump()); err != nil {
		return err
	}
	return nil
}

// Handler handles connection between client and MySQL db
type Handler struct {
	responseHandler      ResponseHandler
	clientSequenceNumber int
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
	logger                 *logrus.Entry
	ctx                    context.Context
	queryObserverManager   base.QueryObserverManager
	decryptionObserver     base.ColumnDecryptionObserver
}

// NewMysqlProxy returns new Handler
func NewMysqlProxy(ctx context.Context, decryptor base.Decryptor, dbConnection, clientConnection net.Conn, tlsConfig *tls.Config, censor acracensor.AcraCensorInterface) (*Handler, error) {
	var newTLSConfig *tls.Config
	if tlsConfig != nil {
		// use less secure protocol versions because some drivers and db images doesn't support secure and modern options
		newTLSConfig = tlsConfig.Clone()
		network.SetMySQLCompatibleTLSSettings(newTLSConfig)
	}
	observerManager, err := base.NewArrayQueryObserverableManager(ctx)
	if err != nil {
		return nil, err
	}
	return &Handler{
		isTLSHandshake:         false,
		dbTLSHandshakeFinished: make(chan bool),
		clientDeprecateEOF:     false,
		decryptor:              decryptor,
		responseHandler:        defaultResponseHandler,
		acracensor:             censor,
		clientConnection:       clientConnection,
		dbConnection:           dbConnection,
		tlsConfig:              newTLSConfig,
		ctx:                    ctx,
		logger:                 logging.GetLoggerFromContext(ctx),
		queryObserverManager:   observerManager,
		decryptionObserver:     base.NewColumnDecryptionObserver(),
	}, nil
}

// SubscribeOnColumnDecryption subscribes for OnColumn notifications about the column, indexed from left to right starting with zero.
func (handler *Handler) SubscribeOnColumnDecryption(i int, subscriber base.DecryptionSubscriber) {
	handler.decryptionObserver.SubscribeOnColumnDecryption(i, subscriber)
}

// SubscribeOnAllColumnsDecryption subscribes for OnColumn notifications on each column.
func (handler *Handler) SubscribeOnAllColumnsDecryption(subscriber base.DecryptionSubscriber) {
	handler.decryptionObserver.SubscribeOnAllColumnsDecryption(subscriber)
}

// Unsubscribe a subscriber from all OnColumn notifications.
func (handler *Handler) Unsubscribe(subscriber base.DecryptionSubscriber) {
	handler.decryptionObserver.Unsubscribe(subscriber)
}

func (handler *Handler) onColumnDecryption(ctx context.Context, column int, data []byte) ([]byte, error) {
	// create new context for current decryption operation
	ctx = base.NewContextWithColumnInfo(ctx, base.NewColumnInfo(column, ""))
	// todo refactor this and pass client/zone id to ctx from other place
	ctx = base.NewContextWithClientZoneInfo(ctx, handler.decryptor.(*Decryptor).clientID, handler.decryptor.GetMatchedZoneID(), handler.decryptor.IsWithZone())
	return handler.decryptionObserver.OnColumnDecryption(ctx, column, data)
}

// AddQueryObserver implement QueryObservable interface and proxy call to ObserverManager
func (handler *Handler) AddQueryObserver(obs base.QueryObserver) {
	handler.queryObserverManager.AddQueryObserver(obs)
}

// RegisteredObserversCount return count of registered observers
func (handler *Handler) RegisteredObserversCount() int {
	return handler.queryObserverManager.RegisteredObserversCount()
}

func (handler *Handler) setQueryHandler(callback ResponseHandler) {
	handler.responseHandler = callback
}
func (handler *Handler) resetQueryHandler() {
	handler.responseHandler = defaultResponseHandler
}

func (handler *Handler) getResponseHandler() ResponseHandler {
	return handler.responseHandler
}

// ProxyClientConnection connects to database, writes data and executes DB commands
func (handler *Handler) ProxyClientConnection(errCh chan<- error) {
	ctx, span := trace.StartSpan(handler.ctx, "ProxyClientConnection")
	defer span.End()
	clientLog := handler.logger.WithField("proxy", "client")
	clientLog.Debugln("Start proxy client's requests")
	firstPacket := true
	prometheusLabels := []string{base.DecryptionDBMysql}
	// use pointers to function where should be stored some function that should be called if code return error and interrupt loop
	// default value empty func to avoid != nil check
	var timerObserveFunc = func() time.Duration { return 0 }
	var packetSpanEndFunc = func() {}
	var censorSpanEndFunc = func() {}
	defer func() {
		timerObserveFunc()
		packetSpanEndFunc()
	}()
	for {
		censorSpanEndFunc()
		timerObserveFunc()
		timer := prometheus.NewTimer(prometheus.ObserverFunc(base.RequestProcessingTimeHistogram.WithLabelValues(prometheusLabels...).Observe))
		timerObserveFunc = timer.ObserveDuration

		packetSpanEndFunc()
		packetSpanCtx, packetSpan := trace.StartSpan(ctx, "ProxyClientConnectionLoop")
		packetSpanEndFunc = packetSpan.End

		packet, err := ReadPacket(handler.clientConnection)
		if err != nil {
			handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorResponseConnectorCantReadFromClient).
				Debugln("Can't read packet from client")
			errCh <- err
			return
		}
		// after reading client's packet we start deadline on write to db side
		handler.dbConnection.SetWriteDeadline(time.Now().Add(network.DefaultNetworkTimeout))
		if firstPacket {
			firstPacket = false
			handler.clientProtocol41 = packet.ClientSupportProtocol41()
			handler.clientDeprecateEOF = packet.IsClientDeprecateEOF()
			clientLog = clientLog.WithField("deprecate_eof", handler.clientDeprecateEOF)
			if packet.IsSSLRequest() {
				if handler.tlsConfig == nil {
					handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).Errorln("To support TLS connections you must pass TLS key and certificate for AcraServer that will be used " +
						"for connections AcraServer->Database and CA certificate which will be used to verify certificate " +
						"from database")
					handler.logger.Debugln("Send error to db")
					errPacket := NewQueryInterruptedError(handler.clientProtocol41)
					packet.SetData(errPacket)
					if _, err := handler.clientConnection.Write(packet.Dump()); err != nil {
						handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorResponseConnectorCantWriteToClient).
							Debugln("Can't write response with error to client")
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
					clientLog.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).WithError(err).Debugln("Can't write send packet to db")
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
				case <-time.NewTicker(time.Second * ClientWaitDbTLSHandshake).C:
					clientLog.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).Errorln("Timeout on tls handshake with db")
					errCh <- errors.New("handshake timeout")
					return
				}
			}
		}
		handler.clientSequenceNumber = int(packet.GetSequenceNumber())
		clientLog = clientLog.WithField("sequence_number", handler.clientSequenceNumber)
		clientLog.Debugln("New packet")
		data := packet.GetData()
		cmd := data[0]
		data = data[1:]
		handler.currentCommand = cmd
		switch cmd {
		case CommandQuit:
			clientLog.Debugln("Close connections on CommandQuit command")
			if _, err := handler.dbConnection.Write(packet.Dump()); err != nil {
				clientLog.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorResponseConnectorCantWriteToDB).
					Debugln("Can't write send packet to db")
				errCh <- err
				return
			}
			handler.clientConnection.Close()
			handler.dbConnection.Close()
			errCh <- io.EOF
			return
		case CommandQuery, CommandStatementPrepare:
			_, censorSpan := trace.StartSpan(packetSpanCtx, "censor")
			query := string(data)

			// log query with hidden values for debug mode
			if logging.GetLogLevel() == logging.LogDebug {
				_, queryWithHiddenValues, _, err := common.HandleRawSQLQuery(query)
				if err == common.ErrQuerySyntaxError {
					clientLog.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).Debugf("Parsing error on query: %s", queryWithHiddenValues)
				} else {
					clientLog.WithFields(logrus.Fields{"sql": queryWithHiddenValues, "command": cmd}).Debugln("Query command")
				}
			}

			if err := handler.acracensor.HandleQuery(query); err != nil {
				censorSpan.End()
				clientLog.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).Errorln("Error on AcraCensor check")
				errPacket := NewQueryInterruptedError(handler.clientProtocol41)
				packet.SetData(errPacket)
				if _, err := handler.clientConnection.Write(packet.Dump()); err != nil {
					handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorResponseConnectorCantWriteToClient).
						Errorln("Can't write response with error to client")
				}
				continue
			}

			newQuery, changed, err := handler.queryObserverManager.OnQuery(base.NewOnQueryObjectFromQuery(query))
			if err != nil {
				clientLog.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorEncryptQueryData).Errorln("Error occurred on query handler")
			} else if changed {
				packet.replaceQuery(newQuery.Query())
			}

			if cmd == CommandQuery {
				handler.setQueryHandler(handler.QueryResponseHandler)
			}
			censorSpan.End()
			break
		case CommandStatementExecute:
			handler.setQueryHandler(handler.QueryResponseHandler)
			break
		case CommandStatementClose, CommandStatementSendLongData, CommandStatementReset:
			clientLog.Debugln("Close|SendLongData|Reset command")
		default:
			clientLog.Debugf("Command %d not supported now", cmd)
		}
		if _, err := handler.dbConnection.Write(packet.Dump()); err != nil {
			clientLog.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).
				Debugln("Can't write send packet to db")
			errCh <- err
			return
		}
	}
}

func (handler *Handler) isFieldToDecrypt(field *ColumnDescription) bool {
	switch field.Type {
	case TypeVarchar, TypeTinyBlob, TypeMediumBlob, TypeLongBlob, TypeBlob,
		TypeVarString, TypeString:
		return true
	default:
		return false
	}
}

func (handler *Handler) processTextDataRow(ctx context.Context, rowData []byte, fields []*ColumnDescription) ([]byte, error) {
	span := trace.FromContext(ctx)
	var err error
	var value []byte
	var pos int
	var n int
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
			if err == nil && decryptedValue != nil && len(decryptedValue) != len(value) {
				base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
				fieldLogger.Debugln("Update with decrypted value")
				output = append(output, PutLengthEncodedString(decryptedValue)...)
			} else {
				if err != errPlainData {
					span.AddAttributes(trace.BoolAttribute("failed_decryption", true))
					base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
				}
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

func (handler *Handler) processBinaryDataRow(ctx context.Context, rowData []byte, fields []*ColumnDescription) ([]byte, error) {
	span := trace.FromContext(ctx)
	pos := 0
	var n int
	var err error
	var value []byte
	var output []byte

	handler.logger.Debugln("Process data rows in binary protocol")
	// no data in response
	if rowData[0] == EOFPacket {
		return rowData, nil
	}

	if rowData[0] != OkPacket {
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
				if err != errPlainData {
					span.AddAttributes(trace.BoolAttribute("failed_decryption", true))
					base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
				}
				handler.logger.Debugln("Leave value as is")
			}
			if decryptedValue != nil && err == nil && len(value) != len(decryptedValue) {
				base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
				output = append(output, PutLengthEncodedString(decryptedValue)...)
			} else {
				output = append(output, rowData[pos:pos+n]...)
			}

			pos += n
			continue
		}
		// https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
		switch fields[i].Type {
		case TypeNull:
			continue

		case TypeTiny:
			output = append(output, rowData[pos])
			pos++
			continue

		case TypeShort, TypeYear:
			output = append(output, rowData[pos:pos+2]...)
			pos += 2
			continue

		case TypeInt24, TypeLong:
			output = append(output, rowData[pos:pos+4]...)
			pos += 4
			continue

		case TypeLongLong:
			output = append(output, rowData[pos:pos+8]...)
			pos += 8
			continue

		case TypeFloat:
			output = append(output, rowData[pos:pos+4]...)
			pos += 4
			continue

		case TypeDouble:
			output = append(output, rowData[pos:pos+8]...)
			pos += 8
			continue

		case TypeDecimal, TypeNewDecimal,
			TypeBit, TypeEnum, TypeSet, TypeGeometry:
			value, _, n, err = LengthEncodedString(rowData[pos:])
			output = append(output, rowData[pos:pos+n]...)
			pos += n
			if err != nil {
				handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).
					Errorln("Can't handle length encoded string non binary value")
				return nil, err
			}
			continue
		case TypeDate, TypeNewDate, TypeTimestamp, TypeDatetime, TypeTime:
			_, _, n, err = LengthEncodedInt(rowData[pos:])
			if err != nil {
				return nil, err
			}
			output = append(output, rowData[pos:pos+n]...)
			pos += n
			continue
		default:
			return nil, fmt.Errorf("found unknown FieldType <type=%d> <name=%s> in MySQL response packet", fields[i].Type, fields[i].Name)
		}
	}
	return output, nil
}

func (handler *Handler) expectEOFOnColumnDefinition() bool {
	return !handler.clientDeprecateEOF
}

func (handler *Handler) isPreparedStatementResult() bool {
	return handler.currentCommand == CommandStatementExecute
}

// QueryResponseHandler parses data from database response
func (handler *Handler) QueryResponseHandler(ctx context.Context, packet *Packet, dbConnection, clientConnection net.Conn) (err error) {
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
	if fieldCount != ErrPacket && fieldCount > 0 {
		handler.logger.Debugln("Read column descriptions")
		for i := 0; ; i++ {
			handler.logger.WithField("column_index", i).Debugln("Read column description")
			fieldPacket, err := ReadPacket(dbConnection)
			if err != nil {
				handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorResponseConnectorCantProcessColumn).
					Debugln("Can't read packet with column description")
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
					handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorProtocolProcessing).WithError(err).Debugln("Can't read data packet")
					return err
				}
				output = append(output, fieldDataPacket)
				if fieldDataPacket.data[0] == EOFPacket {
					break
				}
				newData, err := handler.processBinaryDataRow(ctx, fieldDataPacket.GetData(), fields)
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
					handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorProtocolProcessing).WithError(err).Debugln("Can't read data packet")
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
				newData, err := handler.processTextDataRow(ctx, fieldDataPacket.GetData(), fields)
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
			handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).
				Debugln("Can't proxy output")
			return err
		}
	}
	handler.resetQueryHandler()
	handler.logger.Debugln("Query handler finish")
	return nil
}

// ProxyDatabaseConnection handles connection from database, returns data to client
func (handler *Handler) ProxyDatabaseConnection(errCh chan<- error) {
	ctx, span := trace.StartSpan(handler.ctx, "ProxyDatabaseConnection")
	defer span.End()
	serverLog := handler.logger.WithField("proxy", "server")
	serverLog.Debugln("Start proxy db responses")
	firstPacket := true
	var responseHandler ResponseHandler
	prometheusLabels := []string{base.DecryptionDBMysql}
	if handler.decryptor.IsWholeMatch() {
		prometheusLabels = append(prometheusLabels, base.DecryptionModeWhole)
	} else {
		prometheusLabels = append(prometheusLabels, base.DecryptionModeInline)
	}
	// use pointers to function where should be stored some function that should be called if code return error and interrupt loop
	// default value empty func to avoid != nil check
	var packetSpanEndFunc = func() {}
	var timerObserveFunc = func() time.Duration { return 0 }
	defer func() {
		timerObserveFunc()
		packetSpanEndFunc()
	}()
	for {
		packetSpanEndFunc()
		_, packetSpan := trace.StartSpan(ctx, "ProxyDatabaseConnectionLoop")
		packetSpanEndFunc = packetSpan.End

		timerObserveFunc()
		timer := prometheus.NewTimer(prometheus.ObserverFunc(base.ResponseProcessingTimeHistogram.WithLabelValues(prometheusLabels...).Observe))
		timerObserveFunc = timer.ObserveDuration

		packet, err := ReadPacket(handler.dbConnection)
		if err != nil {
			if netErr, ok := err.(net.Error); ok {
				if netErr.Timeout() && handler.isTLSHandshake {
					// reset deadline
					handler.dbConnection.SetReadDeadline(time.Time{})
					tlsConnection := tls.Client(handler.dbConnection, handler.tlsConfig)
					if err = tlsConnection.Handshake(); err != nil {
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
		// after reading response from db response set deadline on writing data to client
		handler.clientConnection.SetWriteDeadline(time.Now().Add(network.DefaultNetworkTimeout))
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
		err = responseHandler(ctx, packet, handler.dbConnection, handler.clientConnection)
		if err != nil {
			handler.resetQueryHandler()
			errCh <- err
			return
		}
	}
}
