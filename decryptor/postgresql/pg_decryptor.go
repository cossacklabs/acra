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

// Package postgresql contains PgDecryptor reads data from PostgreSQL databases, finds AcraStructs and decrypt them.
package postgresql

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	acracensor "github.com/cossacklabs/acra/acra-censor"
	"github.com/cossacklabs/acra/acra-censor/common"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/utils"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
)

// ReadyForQueryPacket - 'Z' ReadyForQuery, 0 0 0 5 length, 'I' idle status
// https://www.postgresql.org/docs/9.3/static/protocol-message-formats.html
var ReadyForQueryPacket = []byte{'Z', 0, 0, 0, 5, 'I'}

// TerminatePacket sent by client to close connection with db
// https://www.postgresql.org/docs/9.4/static/protocol-message-formats.html
var TerminatePacket = []byte{'X', 0, 0, 0, 4}

// NewPgError returns packed error
func NewPgError(message string) ([]byte, error) {
	// 5 = E marker + 4 bytes for message length
	// 7 is severity error with null terminator
	// +1 for null terminator of message and packet
	output := make([]byte, 5+7+7+len(message)+2)
	// error message
	output[0] = 'E'
	// leave untouched place for length of data
	output = output[:5]
	// error severity
	output = append(output, []byte{'S', 'E', 'R', 'R', 'O', 'R', 0}...)
	// 42000 - syntax_error_or_access_rule_violation
	// https://www.postgresql.org/docs/9.3/static/errcodes-appendix.html
	output = append(output, []byte("C42000")...)
	output = append(output, 0)
	// human readable message
	output = append(output, append([]byte{'M'}, []byte(message)...)...)
	output = append(output, 0, 0)
	// place length of data
	// -1 byte to exclude type of message
	// 1:5 4 bytes for packet length without first byte of message type
	binary.BigEndian.PutUint32(output[1:5], uint32(len(output)-1))
	return output, nil
}

// Errors returned when initializing session registries.
var (
	ErrInvalidPreparedStatementRegistry = errors.New("ClientSession contains invalid PreparedStatementRegistry")
	ErrInvalidCursorRegistry            = errors.New("ClientSession contains invalid CursorRegistry")
	ErrInvalidProtocolState             = errors.New("ClientSession contains invalid ProtocolState")
)

// PgSQL constant sizes and types.
const (
	// DataRowLengthBufSize each postgresql packet contain 4 byte that store length of message contents in bytes, including self
	DataRowLengthBufSize = 4
	// random chosen
	OutputDefaultSize = 1024
	// https://www.postgresql.org/docs/9.4/static/protocol-message-formats.html
	DataRowMessageType       byte = 'D'
	QueryMessageType         byte = 'Q'
	ParseMessageType         byte = 'P'
	BindMessageType          byte = 'B'
	ParseCompleteMessageType byte = '1'
	BindCompleteMessageType  byte = '2'
	ReadyForQueryMessageType byte = 'Z'
	TLSTimeout                    = time.Second * 2
)

// PgProxy represents PgSQL database connection between client and database with TLS support
type PgProxy struct {
	session              base.ClientSession
	clientConnection     net.Conn
	dbConnection         net.Conn
	TLSCh                chan bool
	ctx                  context.Context
	queryObserverManager base.QueryObserverManager
	clientTLSConfig      *tls.Config
	dbTLSConfig          *tls.Config
	censor               acracensor.AcraCensorInterface
	decryptor            base.Decryptor
	tlsSwitch            bool
	decryptionObserver   base.ColumnDecryptionObserver
	protocolState        *PgProtocolState
}

// NewPgProxy returns new PgProxy
func NewPgProxy(session base.ClientSession, decryptor base.Decryptor, setting base.ProxySetting) (*PgProxy, error) {
	observerManager, err := base.NewArrayQueryObserverableManager(session.Context())
	if err != nil {
		return nil, err
	}
	if session.PreparedStatementRegistry() == nil {
		session.SetPreparedStatementRegistry(NewPreparedStatementRegistry())
	}
	var protocolState *PgProtocolState
	if session.ProtocolState() != nil {
		var ok bool
		protocolState, ok = session.ProtocolState().(*PgProtocolState)
		if !ok {
			return nil, ErrInvalidProtocolState
		}
	} else {
		protocolState = NewPgProtocolState()
		session.SetProtocolState(protocolState)
	}
	return &PgProxy{
		session:              session,
		clientConnection:     session.ClientConnection(),
		dbConnection:         session.DatabaseConnection(),
		TLSCh:                make(chan bool),
		ctx:                  session.Context(),
		queryObserverManager: observerManager,
		clientTLSConfig:      setting.ClientTLSConfig(),
		dbTLSConfig:          setting.DatabaseTLSConfig(),
		censor:               setting.Censor(),
		decryptor:            decryptor,
		decryptionObserver:   base.NewColumnDecryptionObserver(),
		protocolState:        protocolState,
	}, nil
}

// SubscribeOnColumnDecryption subscribes for notifications about the column, indexed from left to right starting with zero.
func (proxy *PgProxy) SubscribeOnColumnDecryption(column int, subscriber base.DecryptionSubscriber) {
	proxy.decryptionObserver.SubscribeOnColumnDecryption(column, subscriber)
}

// SubscribeOnAllColumnsDecryption subscribes for notifications on each column.
func (proxy *PgProxy) SubscribeOnAllColumnsDecryption(subscriber base.DecryptionSubscriber) {
	proxy.decryptionObserver.SubscribeOnAllColumnsDecryption(subscriber)
}

// Unsubscribe a subscriber from all notifications.
func (proxy *PgProxy) Unsubscribe(subscriber base.DecryptionSubscriber) {
	proxy.decryptionObserver.Unsubscribe(subscriber)
}

func (proxy *PgProxy) onColumnDecryption(ctx context.Context, i int, data []byte) ([]byte, error) {
	// create new context for current decryption operation
	ctx = base.NewContextWithColumnInfo(ctx, base.NewColumnInfo(i, ""))
	// todo refactor this and pass client/zone id to ctx from other place
	ctx = base.NewContextWithClientZoneInfo(ctx, proxy.decryptor.(*PgDecryptor).clientID, proxy.decryptor.GetMatchedZoneID(), proxy.decryptor.IsWithZone())
	return proxy.decryptionObserver.OnColumnDecryption(ctx, i, data)
}

// AddQueryObserver implement QueryObservable interface and proxy call to ObserverManager
func (proxy *PgProxy) AddQueryObserver(obs base.QueryObserver) {
	proxy.queryObserverManager.AddQueryObserver(obs)
}

// RegisteredObserversCount return count of registered observers
func (proxy *PgProxy) RegisteredObserversCount() int {
	return proxy.queryObserverManager.RegisteredObserversCount()
}

// ProxyClientConnection checks every client request using AcraCensor,
// if request is allowed, sends it to the Pg database
func (proxy *PgProxy) ProxyClientConnection(errCh chan<- error) {
	ctx, span := trace.StartSpan(proxy.ctx, "ProxyClientConnection")
	defer span.End()
	logger := logging.NewLoggerWithTrace(ctx).WithField("proxy", "client")
	logger.Debugln("ProxyClientConnection")
	writer := bufio.NewWriter(proxy.dbConnection)

	reader := bufio.NewReader(proxy.clientConnection)
	packet, err := NewClientSidePacketHandler(reader, writer, logger)
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlPacketHandlerInitiailization).WithError(err).Errorln("Can't initialize packet handler object")
		errCh <- err
		return
	}
	prometheusLabels := []string{base.DecryptionDBPostgresql}
	// use pointers to function where should be stored some function that should be called if code return error and interrupt loop
	// default value empty func to avoid != nil check
	var spanEndFunc = func() {}
	var timerObserveFunc = func() time.Duration { return 0 }
	// always call span.End for case if was error
	defer func() {
		spanEndFunc()
		timerObserveFunc()
	}()
	for {
		timerObserveFunc()
		timer := prometheus.NewTimer(prometheus.ObserverFunc(base.RequestProcessingTimeHistogram.WithLabelValues(prometheusLabels...).Observe))
		timerObserveFunc = timer.ObserveDuration

		packet.Reset()

		spanEndFunc()
		packetSpanCtx, packetSpan := trace.StartSpan(ctx, "ProxyClientConnectionLoop")
		spanEndFunc = packetSpan.End

		if err = packet.ReadClientPacket(); err != nil {
			if proxy.tlsSwitch {
				proxy.tlsSwitch = false
				proxy.TLSCh <- true
				return
			}
			// log message with debug level because only here we expect and can meet errors with closed connections io.EOF
			logger.WithError(err).Debugln("Can't read packet from client to database")
			errCh <- err
			return
		}
		proxy.dbConnection.SetWriteDeadline(time.Now().Add(network.DefaultNetworkTimeout))

		_, censorSpan := trace.StartSpan(packetSpanCtx, "censor")

		// Massage the packet. This should not normally fail. If it does, the database will not receive the packet.
		censored, err := proxy.handleClientPacket(packet, logger)
		if err != nil {
			errCh <- err
			return
		}

		censorSpan.End()

		// If the packet has been rejected by AcraCensor, stop here and don't send it to the database.
		// Also, craft and send the client an error so that they know their query has been rejected.
		if censored {
			err := proxy.sendClientAcraCensorError(logger)
			if err != nil {
				errCh <- err
				return
			}
			continue
		}

		// After tha packet has been observed and possibly modified, forward it to the database.
		if err := packet.sendPacket(); err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).
				WithError(err).Errorln("Can't send packet")
			errCh <- err
			return
		}
		// If this is a termination packet, we're done here. Signal EOF and stop the proxy.
		if packet.terminatePacket {
			errCh <- io.EOF
			return
		}
	}
}

func (proxy *PgProxy) handleClientPacket(packet *PacketHandler, logger *log.Entry) (bool, error) {
	// Let the protocol observer take a look at the packet, keeping note of it.
	err := proxy.protocolState.HandleClientPacket(packet)
	if err != nil {
		return false, err
	}
	switch proxy.protocolState.LastPacketType() {
	case SimpleQueryPacket, ParseStatementPacket:
		// If that's some sort of a packet with a query inside it,
		// process inline data if necessary and remember the query to handle future response.
		return proxy.handleQueryPacket(packet, logger)

	default:
		// Forward all other uninteresting packets to the database without processing.
		return false, nil
	}
}

func (proxy *PgProxy) handleQueryPacket(packet *PacketHandler, logger *log.Entry) (bool, error) {
	query := proxy.protocolState.PendingQuery()

	// Log query text -- if and only if we're in debug mode -- without inserted value data.
	// The query can still be sensitive though, so only in debug mode can we do this.
	if logging.GetLogLevel() == logging.LogDebug {
		_, queryWithHiddenValues, _, err := common.HandleRawSQLQuery(query.Query())
		if err == common.ErrQuerySyntaxError {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).
				Debugf("Parsing error on query: %s", queryWithHiddenValues)
		} else {
			log := logger.WithField("sql", queryWithHiddenValues)
			if proxy.protocolState.LastPacketType() == ParseStatementPacket {
				preparedStatement := proxy.protocolState.PendingParse()
				log = log.WithField("prepared_name", preparedStatement.Name())
			}
			log.Debugln("New query")
		}
	}

	// Let AcraCensor take a look at the query text.
	// If it's not okay (and we're still alive), don't let the database see the query.
	if censorErr := proxy.censor.HandleQuery(query.Query()); censorErr != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).
			WithError(censorErr).Errorln("AcraCensor blocked query")
		return true, nil
	}

	// Let the registered observers observe the query, potentially modifying it (e.g., transparent encryption).
	newQuery, changed, err := proxy.queryObserverManager.OnQuery(query)
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorEncryptQueryData).
			Errorln("Error occurred on query handler")
	}
	if changed {
		packet.ReplaceQuery(newQuery.Query())
	}
	return false, nil
}

func (proxy *PgProxy) sendClientAcraCensorError(logger *log.Entry) error {
	errorMessage, err := NewPgError("AcraCensor blocked this query")
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantGenerateErrorPacket).
			WithError(err).Errorln("Can't create PostgreSQL error message")
		return err
	}
	n, err := proxy.clientConnection.Write(errorMessage)
	if err := base.CheckReadWrite(n, len(errorMessage), err); err != nil {
		return err
	}
	n, err = proxy.clientConnection.Write(ReadyForQueryPacket)
	if err := base.CheckReadWrite(n, len(ReadyForQueryPacket), err); err != nil {
		return err
	}
	return nil
}

// handlePoisonCheckResult return error err != nil, if can't check on poison record or any callback on poison record
// return error
func handlePoisonCheckResult(decryptor base.Decryptor, poisoned bool, err error, logger *log.Entry) error {
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(err).Errorln("Can't check on poison record")
		return err
	}

	if poisoned {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorRecognizedPoisonRecord).Warningln("Recognized poison record")
		callbacks := decryptor.GetPoisonCallbackStorage()
		if callbacks.HasCallbacks() {
			return callbacks.Call()
		}
	}
	return nil
}

// checkInlinePoisonRecordInBlock check block on poison record as whole AcraStruct block (only when IsPoisonRecordCheckOn() == true)
func checkInlinePoisonRecordInBlock(block []byte, decryptor base.Decryptor, logger *log.Entry) error {
	// check is it Poison Record
	if decryptor.IsPoisonRecordCheckOn() && len(block) > base.GetMinAcraStructLength() {
		logger.Debugln("Check poison records")
		currentIndex := 0
		for {
			index, _ := decryptor.BeginTagIndex(block[currentIndex:])
			if index == utils.NotFound {
				return nil
			}
			if len(block[index:]) < base.GetMinAcraStructLength() {
				break
			}
			acrastructLength := base.GetDataLengthFromAcraStruct(block[currentIndex:]) + base.GetMinAcraStructLength()
			if acrastructLength > 0 && acrastructLength <= len(block[currentIndex:]) {
				currentIndex += index
				endIndex := currentIndex + acrastructLength
				if err := checkWholePoisonRecord(block[currentIndex:endIndex], decryptor, logger); err != nil {
					return err
				}
			}
			currentIndex++
		}
	}
	return nil
}

func checkWholePoisonRecord(block []byte, decryptor base.Decryptor, logger *log.Entry) error {
	if !decryptor.IsPoisonRecordCheckOn() && len(block) < base.GetMinAcraStructLength() {
		return nil
	}
	decryptor.Reset()
	poisoned, checkErr := decryptor.CheckPoisonRecord(bytes.NewReader(block))
	if innerErr := handlePoisonCheckResult(decryptor, poisoned, checkErr, logger); innerErr != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(innerErr).Errorln("Error on poison record check")
		return innerErr
	}
	return checkErr
}

// handleSSLRequest return wrapped with tls (client's, db's connections, nil) or (nil, nil, error)
func (proxy *PgProxy) handleSSLRequest(packet *PacketHandler, logger *log.Entry) (net.Conn, net.Conn, error) {
	// if server allow SSLRequest than we wrap our connections with tls
	if proxy.dbTLSConfig == nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).Errorln("To support TLS connections you must pass TLS key and certificate for AcraServer that will be used " +
			"for connections AcraServer->Database and CA certificate which will be used to verify certificate " +
			"from database")
		return nil, nil, network.ErrEmptyTLSConfig
	}
	logger.Debugln("Start tls proxy")
	proxy.tlsSwitch = true
	// stop reading from client in goroutine
	if err := proxy.clientConnection.SetDeadline(time.Now()); err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantSetDeadlineToClientConnection).
			Errorln("Can't set deadline")
		return nil, nil, err
	}
	select {
	case <-proxy.TLSCh:
		proxy.TLSCh = nil
		break
	case <-time.NewTimer(TLSTimeout).C:
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).Errorln("Can't stop background goroutine to start tls handshake")
		return nil, nil, errors.New("can't stop background goroutine")
	}
	logger.Debugln("Stop client connection")
	if err := proxy.clientConnection.SetDeadline(time.Time{}); err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantSetDeadlineToClientConnection).
			Errorln("Can't set deadline")
		return nil, nil, err
	}
	logger.Debugln("Init tls with client")
	// convert to tls connection
	tlsClientConnection := tls.Server(proxy.clientConnection, proxy.clientTLSConfig)

	// send server's response only after successful interrupting background goroutine that process client's connection
	// to take control over connection and avoid two places that communicate with one connection
	if err := packet.sendMessageType(); err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
			Errorln("Can't send ssl allow packet")
		return nil, nil, err
	}
	if err := tlsClientConnection.Handshake(); err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
			Errorln("Can't initialize tls connection with client")
		return nil, nil, err
	}

	logger.Debugln("Init tls with db")
	dbTLSConnection := tls.Client(proxy.dbConnection, proxy.dbTLSConfig)
	if err := dbTLSConnection.Handshake(); err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
			Errorln("Can't initialize tls connection with db")
		return nil, nil, err
	}
	return tlsClientConnection, dbTLSConnection, nil
}

// ProxyDatabaseConnection process data rows from database
func (proxy *PgProxy) ProxyDatabaseConnection(errCh chan<- error) {
	ctx, span := trace.StartSpan(proxy.ctx, "PgDecryptStream")
	defer span.End()
	logger := logging.NewLoggerWithTrace(ctx).WithField("proxy", "server")
	if proxy.decryptor.IsWholeMatch() {
		logger = logger.WithField("decrypt_mode", "wholecell")
	} else {
		logger = logger.WithField("decrypt_mode", "inline")
	}
	logger.Debugln("Pg db proxy")
	// use buffered writer because we generate response by parts
	writer := bufio.NewWriter(proxy.clientConnection)

	reader := bufio.NewReader(proxy.dbConnection)
	packetHandler, err := NewDbSidePacketHandler(reader, writer, logger)
	if err != nil {
		errCh <- err
		return
	}

	prometheusLabels := []string{base.DecryptionDBPostgresql}
	if proxy.decryptor.IsWholeMatch() {
		prometheusLabels = append(prometheusLabels, base.DecryptionModeWhole)
	} else {
		prometheusLabels = append(prometheusLabels, base.DecryptionModeInline)
	}
	firstByte := true
	// use pointer to function where should be stored some function that should be called if code return error and interrupt loop
	// default value empty func to avoid != nil check
	var endLoopSpanFunc = func() {}
	defer func() {
		endLoopSpanFunc()
	}()
	for {
		// end span of previous iteration
		endLoopSpanFunc()
		packetCtx, packetSpan := trace.StartSpan(ctx, "PgDecryptStreamLoop")
		endLoopSpanFunc = packetSpan.End

		packetHandler.Reset()
		if firstByte {
			packetSpan.AddAttributes(trace.BoolAttribute("startup", true))
			timer := prometheus.NewTimer(prometheus.ObserverFunc(base.ResponseProcessingTimeHistogram.WithLabelValues(prometheusLabels...).Observe))
			// https://www.postgresql.org/docs/9.1/static/protocol-flow.html#AEN92112
			// we should know that we shouldn't read anymore bytes
			// first response from server may contain only one byte of response on SSLRequest
			firstByte = false
			logger.Debugln("Read startup message")
			if err = packetHandler.readMessageType(); err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).WithError(err).Debugln("Can't read first message type")
				errCh <- err
				return
			}
			if packetHandler.IsSSLRequestDeny() {
				logger.Debugln("Deny ssl request")
				if err = packetHandler.sendMessageType(); err != nil {
					errCh <- err
					return
				}
				timer.ObserveDuration()
				//firstByte = true
				continue
			} else if packetHandler.IsSSLRequestAllowed() {
				tlsClientConnection, dbTLSConnection, err := proxy.handleSSLRequest(packetHandler, logger)
				if err != nil {
					logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).WithError(err).Errorln("Can't process SSL request")
					errCh <- err
					return
				}
				proxy.clientConnection = tlsClientConnection
				proxy.dbConnection = dbTLSConnection
				// restart proxing client's requests
				go proxy.ProxyClientConnection(errCh)
				reader = bufio.NewReader(dbTLSConnection)
				writer = bufio.NewWriter(tlsClientConnection)
				firstByte = true

				packetHandler.reader = reader
				packetHandler.writer = writer
				packetHandler.Reset()
				timer.ObserveDuration()
				continue
			}
			logger.Debugln("Non-ssl request start up message")
			// if it is not ssl request than we just forward it to client
			if err = packetHandler.readData(true); err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).WithError(err).Errorln("Can't read data of packet")
				errCh <- err
				return
			}
			if err = packetHandler.sendPacket(); err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).WithError(err).Errorln("Can't forward first packet")
				errCh <- err
				return
			}
			timer.ObserveDuration()
			continue
		}
		timer := prometheus.NewTimer(prometheus.ObserverFunc(base.ResponseProcessingTimeHistogram.WithLabelValues(prometheusLabels...).Observe))
		if err = packetHandler.ReadPacket(); err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).WithError(err).Debugln("Can't read packet")
			errCh <- err
			return
		}
		proxy.clientConnection.SetWriteDeadline(time.Now().Add(network.DefaultNetworkTimeout))

		// Massage the packet. This should not normally fail. If it does, the client will not receive the packet.
		err := proxy.handleDatabasePacket(packetCtx, packetHandler, logger)
		if err != nil {
			errCh <- err
			return
		}

		// After tha packet has been observed and possibly modified, forward it to the client.
		if err = packetHandler.sendPacket(); err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).
				WithError(err).Errorln("Can't send packet")
			errCh <- err
			return
		}
		timer.ObserveDuration()
	}
}

func (proxy *PgProxy) handleDatabasePacket(ctx context.Context, packet *PacketHandler, logger *log.Entry) error {
	// Let the protocol observer take a look at the packet, keeping note of it.
	err := proxy.protocolState.HandleDatabasePacket(packet)
	if err != nil {
		return err
	}
	switch proxy.protocolState.LastPacketType() {
	case DataPacket:
		// If that's some sort of a packet with a query response inside it,
		// decrypt and process the data in it.
		return proxy.handleQueryDataPacket(ctx, packet, logger)

	case ParseCompletePacket:
		// Previously requested prepared statement has been confirmed by the database, register it.
		preparedStatement := proxy.protocolState.PendingParse()
		return proxy.registerPreparedStatement(preparedStatement, logger)

	default:
		// Forward all other uninteresting packets to the client without processing.
		return nil
	}
}

func (proxy *PgProxy) handleQueryDataPacket(ctx context.Context, packet *PacketHandler, logger *log.Entry) error {
	logger.Debugln("Matched data row packet")
	if err := packet.parseColumns(); err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantParseColumnsDescription).
			WithError(err).Errorln("Can't parse columns in packet")
		return err
	}
	// If the packet does not contain columns to decrypt, we have nothing more to do here.
	if packet.columnCount == 0 {
		return nil
	}

	logger.Debugf("Process columns data")
	for i := 0; i < packet.columnCount; i++ {
		column := packet.Columns[i]
		if column.IsNull() {
			continue
		}
		newData, err := proxy.onColumnDecryption(ctx, i, column.GetData())
		if err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
				WithError(err).Errorln("Error on column data processing")
			return err
		}
		column.SetData(newData)
	}
	// After we're done processing the columns, update the actual packet data from them.
	proxy.decryptor.ResetZoneMatch()
	packet.updateDataFromColumns()
	return nil
}

func (proxy *PgProxy) registerPreparedStatement(preparedStatement *ParsePacket, logger *log.Entry) error {
	name := preparedStatement.Name()
	queryText := preparedStatement.QueryString()
	// This should be always successful since the database filters invalid queries.
	query, err := sqlparser.Parse(queryText)
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("Can't parse SQL from Parse packet")
		return err
	}
	statement := NewPreparedStatement(name, queryText, query)
	registry := proxy.session.PreparedStatementRegistry()
	err = registry.AddStatement(statement)
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("Failed to add prepared statement")
		return err
	}
	logger.WithField("prepared_name", name).Debug("Registered new prepared statement")
	return nil
}
