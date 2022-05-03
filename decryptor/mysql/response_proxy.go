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
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/sqlparser"
	"go.opencensus.io/trace"

	acracensor "github.com/cossacklabs/acra/acra-censor"
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

// Type used for defining MySQL types
type Type byte

// StorageByte represent amount of bytes need to store MySQL type
type StorageByte int

// NumericTypesStorageBytes return association between numeric types and amount of bytes used for their storing
var NumericTypesStorageBytes = map[Type]StorageByte{
	TypeTiny:     StorageByte(1),
	TypeShort:    StorageByte(2),
	TypeYear:     StorageByte(2),
	TypeLong:     StorageByte(4),
	TypeFloat:    StorageByte(4),
	TypeInt24:    StorageByte(4),
	TypeDouble:   StorageByte(8),
	TypeLongLong: StorageByte(8),
	TypeNull:     StorageByte(0),
}

// Bits return number of bits of the StorageByte
func (s StorageByte) Bits() int {
	return int(s) * 8
}

// IsBinaryType true if field type is binary
func (t Type) IsBinaryType() bool {
	isBlob := t >= TypeTinyBlob && t <= TypeBlob
	isString := t == TypeVarString || t == TypeString
	return isString || isBlob || t == TypeVarchar
}

// Binary ColumnTypes https://dev.mysql.com/doc/internals/en/com-query-response.html#column-type
const (
	TypeDecimal Type = iota
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
	TypeNewDecimal Type = iota + 0xf6
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
	clientDeprecateEOF      bool
	acracensor              acracensor.AcraCensorInterface
	isTLSHandshake          bool
	dbTLSHandshakeFinished  chan bool
	clientConnection        net.Conn
	dbConnection            net.Conn
	logger                  *logrus.Entry
	ctx                     context.Context
	queryObserverManager    base.QueryObserverManager
	decryptionObserver      base.ColumnDecryptionObserver
	setting                 base.ProxySetting
	clientIDObserverManager base.ClientIDObservableManager
	parser                  *sqlparser.Parser
	protocolState           *ProtocolState
	registry                *PreparedStatementRegistry
}

// NewMysqlProxy returns new Handler
func NewMysqlProxy(session base.ClientSession, parser *sqlparser.Parser, setting base.ProxySetting) (*Handler, error) {
	observerManager, err := base.NewArrayQueryObservableManager(session.Context())
	if err != nil {
		return nil, err
	}
	clientIDManager, err := base.NewArrayClientIDObservableManager(session.Context())
	if err != nil {
		return nil, err
	}
	return &Handler{
		isTLSHandshake:          false,
		dbTLSHandshakeFinished:  make(chan bool),
		clientDeprecateEOF:      false,
		responseHandler:         defaultResponseHandler,
		acracensor:              setting.Censor(),
		clientConnection:        session.ClientConnection(),
		dbConnection:            session.DatabaseConnection(),
		setting:                 setting,
		ctx:                     session.Context(),
		logger:                  logging.GetLoggerFromContext(session.Context()),
		queryObserverManager:    observerManager,
		decryptionObserver:      base.NewColumnDecryptionObserver(),
		clientIDObserverManager: clientIDManager,
		parser:                  parser,
		protocolState:           NewProtocolState(),
		registry:                NewPreparedStatementRegistry(),
	}, nil
}

// SubscribeOnAllColumnsDecryption subscribes for OnColumn notifications on each column.
func (handler *Handler) SubscribeOnAllColumnsDecryption(subscriber base.DecryptionSubscriber) {
	handler.decryptionObserver.SubscribeOnAllColumnsDecryption(subscriber)
}

// Unsubscribe a subscriber from all OnColumn notifications.
func (handler *Handler) Unsubscribe(subscriber base.DecryptionSubscriber) {
	handler.decryptionObserver.Unsubscribe(subscriber)
}

func (handler *Handler) onColumnDecryption(parentCtx context.Context, column int, data []byte, isBinary bool, field *ColumnDescription) (context.Context, []byte, error) {
	accessContext := base.AccessContextFromContext(parentCtx)
	accessContext.SetColumnInfo(base.NewColumnInfo(column, "", isBinary, len(data), byte(field.Type), byte(field.originType)))
	return handler.decryptionObserver.OnColumnDecryption(parentCtx, column, data)
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
func (handler *Handler) ProxyClientConnection(ctx context.Context, errCh chan<- base.ProxyError) {
	ctx, span := trace.StartSpan(ctx, "ProxyClientConnection")
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
	for {
		censorSpanEndFunc()
		timerObserveFunc()
		packetSpanEndFunc()

		packet, err := ReadPacket(handler.clientConnection)
		if err != nil {
			handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorResponseConnectorCantReadFromClient).
				Debugln("Can't read packet from client")
			errCh <- base.NewClientProxyError(err)
			return
		}

		timer := prometheus.NewTimer(prometheus.ObserverFunc(base.RequestProcessingTimeHistogram.WithLabelValues(prometheusLabels...).Observe))
		timerObserveFunc = timer.ObserveDuration

		packetSpanCtx, packetSpan := trace.StartSpan(ctx, "ProxyClientConnectionLoop")
		packetSpanEndFunc = packetSpan.End

		// after reading client's packet we start deadline on write to db side
		handler.dbConnection.SetWriteDeadline(time.Now().Add(network.DefaultNetworkTimeout))
		if firstPacket {
			firstPacket = false
			handler.clientProtocol41 = packet.ClientSupportProtocol41()
			handler.clientDeprecateEOF = packet.IsClientDeprecateEOF()
			clientLog = clientLog.WithField("deprecate_eof", handler.clientDeprecateEOF)
			if packet.IsSSLRequest() {
				if handler.setting.TLSConnectionWrapper() == nil {
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
					errCh <- base.NewClientProxyError(network.ErrEmptyTLSConfig)
					return
				}

				tlsConnection, clientID, err := handler.setting.TLSConnectionWrapper().WrapClientConnection(handler.ctx, handler.clientConnection)
				if err != nil {
					handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
						Errorln("Error in tls handshake with client")
					var crlErr *network.CRLError
					if network.IsClientBadRecordMacError(err) {
						handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
							Infoln(network.ClientSideBadMacErrorSuggestion)
					} else if network.IsClientUnknownCAError(err) {
						handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
							Infoln(network.ClientSideUnknownCAErrorSuggestion)
					} else if network.IsMissingClientCertificate(err) {
						handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
							Infoln(network.ClientSideNoCertificateErrorSuggestion)
					} else if errors.As(err, &crlErr) {
						handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
							Infoln(network.CRLCheckErrorSuggestion)
					}
					errCh <- base.NewClientProxyError(err)
					return
				}
				if handler.setting.TLSConnectionWrapper().UseConnectionClientID() {
					handler.logger.WithField("client_id", clientID).Debugln("Set new clientID")
					handler.clientIDObserverManager.OnNewClientID(clientID)
				}
				handler.logger.Debugln("Switched to tls with client. wait switching with db")
				handler.isTLSHandshake = true
				handler.clientConnection = tlsConnection
				if _, err := handler.dbConnection.Write(packet.Dump()); err != nil {
					clientLog.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).WithError(err).Debugln("Can't write send packet to db")
					errCh <- base.NewClientProxyError(err)
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
					errCh <- base.NewClientProxyError(errors.New("handshake timeout"))
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
				errCh <- base.NewClientProxyError(err)
				return
			}
			handler.clientConnection.Close()
			handler.dbConnection.Close()
			errCh <- base.NewClientProxyError(io.EOF)
			return
		case CommandQuery, CommandStatementPrepare:
			_, censorSpan := trace.StartSpan(packetSpanCtx, "censor")
			query := string(data)

			// log query with hidden values for debug mode
			if logging.GetLogLevel() == logging.LogDebug {
				_, queryWithHiddenValues, _, err := handler.parser.HandleRawSQLQuery(query)
				if err == sqlparser.ErrQuerySyntaxError {
					clientLog.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).Debugf("Parsing error on query: %s", queryWithHiddenValues)
				} else {
					debugCmd := "Query command"
					if cmd == CommandStatementPrepare {
						debugCmd = "Prepared Statement command"
					}
					clientLog.WithFields(logrus.Fields{"sql": queryWithHiddenValues, "command": cmd}).Debugln(debugCmd)
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

			queryObj := base.NewOnQueryObjectFromQuery(query, handler.parser)
			newQuery, changed, err := handler.queryObserverManager.OnQuery(ctx, queryObj)
			if err != nil {
				if filesystem.IsKeyReadError(err) {
					errCh <- base.NewClientProxyError(err)
					return
				}
				clientLog.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorEncryptQueryData).Errorln("Error occurred on query handler")
			} else if changed {
				packet.replaceQuery(newQuery.Query())
			}

			switch cmd {
			case CommandQuery:
				handler.setQueryHandler(handler.QueryResponseHandler)
			case CommandStatementPrepare:
				handler.protocolState.SetPendingParse(queryObj)
				handler.setQueryHandler(handler.PreparedStatementResponseHandler)
			}

			censorSpan.End()
			break
		case CommandStatementExecute:
			if err = handler.handleStatementExecute(ctx, packet); err != nil {
				errCh <- base.NewClientProxyError(err)
				return
			}

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
			errCh <- base.NewClientProxyError(err)
			return
		}
	}
}

func (handler *Handler) handleStatementExecute(ctx context.Context, packet *Packet) error {
	stmtID := binary.LittleEndian.Uint32(packet.GetData()[1:])

	log := handler.logger.WithField("proxy", "client").WithField("statement", stmtID)
	log.Debug("Statement Execute")

	statement, err := handler.registry.StatementByID(strconv.FormatUint(uint64(stmtID), 10))
	if err != nil {
		log.WithError(err).Error("Can't find prepared statement in registry")
		return nil
	}

	parameters, err := packet.GetBindParameters(statement.ParamsNum())
	if err != nil {
		log.WithError(err).Error("Can't parse OnBind parameters")
		return nil
	}

	newParameters, changed, err := handler.queryObserverManager.OnBind(ctx, statement.Query(), parameters)
	if err != nil {
		// Security: here we should interrupt proxying in case of any keys read related errors
		// in other cases we just stop the processing to let db protocol handle the error.
		if filesystem.IsKeyReadError(err) {
			return err
		}

		log.WithError(err).Error("Failed to handle Bind packet")
		return nil
	}

	// Finally, if the parameter values have been changed, update the packet.
	// If that fails, send the packet unchanged, as usual.
	if changed {
		err := packet.SetParameters(newParameters)
		if err != nil {
			log.WithError(err).Error("Failed to update Bind packet")
			return nil
		}
	}

	return nil
}

func (handler *Handler) processTextDataRow(ctx context.Context, rowData []byte, fields []*ColumnDescription) (output []byte, err error) {
	var pos int
	var fieldLogger *logrus.Entry
	handler.logger.Debugln("Process data rows in text protocol")
	for i := range fields {
		fieldLogger = handler.logger.WithField("field_index", i)
		value, n, err := base.LengthEncodedString(rowData[pos:])
		if err != nil {
			return nil, err
		}

		decrCtx, value, err := handler.onColumnDecryption(ctx, i, value, false, fields[i])
		if err != nil {
			fieldLogger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
				WithError(err).Errorln("Failed to process column data")
			return nil, err
		}

		// rollback type changing in case of error converting to data type
		if base.IsErrorConvertedDataTypeFromContext(decrCtx) {
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
				WithField("field_index", i).WithError(err).Errorln("Failed to change data type - rollback field type")
			fields[i].Type = fields[i].originType
		}

		output = append(output, value...)
		pos += n
	}
	handler.logger.Debugln("Finish processing text data row")

	return output, nil
}

func (handler *Handler) processBinaryDataRow(ctx context.Context, rowData []byte, fields []*ColumnDescription) ([]byte, error) {
	pos := 0
	var output []byte

	handler.logger.Debugln("Process data rows in binary protocol")
	// no data in response
	if rowData[0] == EOFPacket {
		return rowData, nil
	}

	if rowData[0] != OkPacket {
		return nil, base.ErrMalformPacket
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
		extractedData, n, err := handler.extractData(pos, rowData, fields[i])
		if err != nil {
			handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).
				Errorln("Can't handle length encoded string binary value")
			return nil, err
		}

		decrCtx, value, err := handler.onColumnDecryption(ctx, i, extractedData, true, fields[i])
		if err != nil {
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
				WithField("field_index", i).WithError(err).Errorln("Failed to process column data")
			return nil, err
		}

		// rollback type changing in case of error converting to data type
		if base.IsErrorConvertedDataTypeFromContext(decrCtx) {
			handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
				WithField("field_index", i).WithError(err).Errorln("Failed to change data type - rollback field type")
			fields[i].Type = fields[i].originType
		}

		output = append(output, value...)
		pos += n
	}
	return output, nil
}

// extractData retrieve positional data from data row
func (handler *Handler) extractData(pos int, rowData []byte, field *ColumnDescription) ([]byte, int, error) {
	// in case of type changing we should process as origin type
	fieldType := field.Type
	if field.changed {
		fieldType = field.originType
	}

	switch fieldType {
	case TypeNull:
		return []byte{}, 0, nil

	case TypeTiny:
		return rowData[pos : pos+1], 1, nil

	case TypeShort, TypeYear:
		return rowData[pos : pos+2], 2, nil

	case TypeInt24, TypeLong:
		return rowData[pos : pos+4], 4, nil

	case TypeLongLong:
		return rowData[pos : pos+8], 8, nil

	case TypeFloat:
		return rowData[pos : pos+4], 4, nil

	case TypeDouble:
		return rowData[pos : pos+8], 8, nil

	case TypeDecimal, TypeNewDecimal, TypeBit, TypeEnum, TypeSet, TypeGeometry, TypeDate, TypeNewDate, TypeTimestamp, TypeDatetime, TypeTime, TypeVarchar, TypeTinyBlob, TypeMediumBlob, TypeLongBlob, TypeBlob, TypeVarString, TypeString:
		value, n, err := base.LengthEncodedString(rowData[pos:])
		if err != nil {
			handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).
				Errorln("Can't handle length encoded string non binary value")
			return nil, 0, err
		}
		return value, n, nil
	default:
		return nil, 0, errors.New("found unknown FieldType in MySQL response packet")
	}
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
			if handler.expectEOFOnColumnDefinition() {
				if fieldPacket.IsEOF() {
					if i != fieldCount {
						handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorProtocolProcessing).Errorln("EOF and field count != current row packet count")
						return base.ErrMalformPacket
					}
					output = append(output, fieldPacket)
					break
				}
			}
			handler.logger.WithField("column_index", i).Debugln("Parse field")
			field, err := ParseResultField(fieldPacket)
			if err != nil {
				handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorProtocolProcessing).WithError(err).Errorln("Can't parse result field")
				return err
			}
			// updating field type according to DataType provided in schemaStore
			updateFieldEncodedType(field, handler.setting.TableSchemaStore())

			if field.Type.IsBinaryType() {
				handler.logger.WithField("column_index", i).Debugln("Binary field")
				binaryFieldIndexes = append(binaryFieldIndexes, i)
			}
			fields = append(fields, field)
			output = append(output, field)
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
				handler.logger.WithFields(logrus.Fields{"oldLength": fieldDataPacket.GetPacketPayloadLength(), "newLength": len(newData)}).Debugln("Update row data")
				fieldDataPacket.SetData(newData)
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
				dataLog.WithFields(logrus.Fields{"oldLength": fieldDataPacket.GetPacketPayloadLength(), "newLength": len(newData)}).Debugln("Update row data")
				fieldDataPacket.SetData(newData)
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

// PreparedStatementResponseHandler handles PreparedStatements response from DB
func (handler *Handler) PreparedStatementResponseHandler(ctx context.Context, packet *Packet, dbConnection, clientConnection net.Conn) (err error) {
	response, err := ParsePrepareStatementResponse(packet.GetData())
	if err != nil {
		handler.logger.WithError(err).Error("Failed to handle prepared statement response packet: can't parse prepared statement DB response")
		return err
	}

	queryObj := handler.protocolState.PendingParse()
	statement, err := queryObj.Statement()
	if err != nil {
		handler.logger.WithError(err).Error("Failed to handle prepared statement response packet: can't find prepared statement")
		return err
	}
	handler.registry.AddStatement(NewPreparedStatement(response, queryObj.Query(), statement))

	// proxy output
	handler.logger.Debugln("Proxy output")
	if _, err := clientConnection.Write(packet.Dump()); err != nil {
		handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).
			Debugln("Can't proxy output")
		return err
	}

	handler.resetQueryHandler()
	// if prams_num > 0 params definition block will follow
	// https://dev.mysql.com/doc/internals/en/com-stmt-prepare-response.html
	if response.ParamsNum > 0 {
		fieldTracker := NewPreparedStatementFieldTracker(handler, response.ColumnsNum)
		handler.setQueryHandler(fieldTracker.ParamsTrackHandler)
	}
	handler.logger.Debugln("Prepared Statement registered successfully")
	return nil
}

// ProxyDatabaseConnection handles connection from database, returns data to client
func (handler *Handler) ProxyDatabaseConnection(ctx context.Context, errCh chan<- base.ProxyError) {
	ctx, span := trace.StartSpan(ctx, "ProxyDatabaseConnection")
	defer span.End()
	serverLog := handler.logger.WithField("proxy", "server")
	serverLog.Debugln("Start proxy db responses")
	firstPacket := true
	var responseHandler ResponseHandler
	// use pointers to function where should be stored some function that should be called if code return error and interrupt loop
	// default value empty func to avoid != nil check
	var packetSpanEndFunc = func() {}
	var timerObserveFunc = func() time.Duration { return 0 }
	for {
		packetSpanEndFunc()
		timerObserveFunc()

		packet, err := ReadPacket(handler.dbConnection)
		if err != nil {
			if netErr, ok := err.(net.Error); ok {
				if netErr.Timeout() && handler.isTLSHandshake {
					// reset deadline
					handler.dbConnection.SetReadDeadline(time.Time{})
					tlsConnection, err := handler.setting.TLSConnectionWrapper().WrapDBConnection(handler.ctx, handler.dbConnection)
					if err != nil {
						handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
							Errorln("Can't initialize tls connection with db")
						var crlErr *network.CRLError
						if network.IsSNIError(err) {
							handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
								Infoln(network.DatabaseSideSNIErrorSuggestion)
						} else if network.IsDatabaseUnknownCAError(err) {
							handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
								Infoln(network.DatabaseSideUnknownCAErrorSuggestions)
						} else if errors.As(err, &crlErr) {
							handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
								Infoln(network.CRLCheckErrorSuggestion)
						}
						errCh <- base.NewDBProxyError(err)
						return
					}
					handler.logger.Debugln("Switched to tls with db")
					handler.dbConnection = tlsConnection
					handler.dbTLSHandshakeFinished <- true
					continue
				}
			}
			handler.logger.Debugln("Can't read packet from server")
			errCh <- base.NewDBProxyError(err)
			return
		}

		_, packetSpan := trace.StartSpan(ctx, "ProxyDatabaseConnectionLoop")
		packetSpanEndFunc = packetSpan.End

		timer := prometheus.NewTimer(prometheus.ObserverFunc(base.ResponseProcessingTimeHistogram.WithLabelValues(base.DecryptionDBMysql).Observe))
		timerObserveFunc = timer.ObserveDuration

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
		// reset previously matched zoneID
		accessContext := base.AccessContextFromContext(ctx)
		accessContext.SetZoneID(nil)
		responseHandler = handler.getResponseHandler()
		err = responseHandler(ctx, packet, handler.dbConnection, handler.clientConnection)
		if err != nil {
			handler.resetQueryHandler()
			errCh <- base.NewDBProxyError(err)
			return
		}
	}
}

// AddClientIDObserver subscribe new observer for clientID changes
func (handler *Handler) AddClientIDObserver(observer base.ClientIDObserver) {
	handler.clientIDObserverManager.AddClientIDObserver(observer)
}
