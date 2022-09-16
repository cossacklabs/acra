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
	"context"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/jackc/pgx/pgtype"

	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"

	acracensor "github.com/cossacklabs/acra/acra-censor"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
)

// ReadyForQuery - 'Z' ReadyForQuery, 0 0 0 5 length, 'I' idle status
// https://www.postgresql.org/docs/9.3/static/protocol-message-formats.html
var ReadyForQuery = []byte{'Z', 0, 0, 0, 5, 'I'}

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
	ExecuteMessageType       byte = 'E'
	ParseCompleteMessageType byte = '1'
	BindCompleteMessageType  byte = '2'
	ReadyForQueryMessageType byte = 'Z'
	RowDescriptionType       byte = 'T'
	ParameterDescriptionType byte = 't'
	ClientStopTimeout             = time.Second * 2
)

// Specific for PgSQL values of data format
// https://www.postgresql.org/docs/9.3/protocol-message-formats.html
const (
	dataFormatText   = 0
	dataFormatBinary = 1
)

type databaseHandlerState int

const (
	// stateFirstPacket is the starting state of the handler. The handler
	// first byte of the response can indicate switching to tls. So, we should
	// not read more than that. This state exists to indicate such special case.
	stateFirstPacket databaseHandlerState = iota
	// stateServe is the most common state of the handler. It means normal
	// processing of packets
	stateServe
	// stateSkipResponse is a state of a handler when it skips a response
	// from database until `ReadyForQuery` is arrived.
	stateSkipResponse
)

// PgProxy represents PgSQL database connection between client and database with TLS support
type PgProxy struct {
	session                 base.ClientSession
	clientConnection        net.Conn
	dbConnection            net.Conn
	stopClient              bool
	ClientStopResponse      chan bool
	ctx                     context.Context
	queryObserverManager    base.QueryObserverManager
	censor                  acracensor.AcraCensorInterface
	decryptionObserver      base.ColumnDecryptionObserver
	protocolState           *PgProtocolState
	setting                 base.ProxySetting
	clientIDObserverManager base.ClientIDObservableManager
	parser                  *sqlparser.Parser
}

// NewPgProxy returns new PgProxy
func NewPgProxy(session base.ClientSession, parser *sqlparser.Parser, setting base.ProxySetting) (*PgProxy, error) {
	observerManager, err := base.NewArrayQueryObservableManager(session.Context())
	if err != nil {
		return nil, err
	}
	clientIDObserverManager, err := base.NewArrayClientIDObservableManager(session.Context())
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
		protocolState = NewPgProtocolState(parser)
		session.SetProtocolState(protocolState)
	}
	return &PgProxy{
		session:                 session,
		clientConnection:        session.ClientConnection(),
		dbConnection:            session.DatabaseConnection(),
		ClientStopResponse:      make(chan bool),
		ctx:                     session.Context(),
		queryObserverManager:    observerManager,
		setting:                 setting,
		censor:                  setting.Censor(),
		decryptionObserver:      base.NewColumnDecryptionObserver(),
		protocolState:           protocolState,
		clientIDObserverManager: clientIDObserverManager,
		parser:                  parser,
	}, nil
}

// SubscribeOnAllColumnsDecryption subscribes for notifications on each column.
func (proxy *PgProxy) SubscribeOnAllColumnsDecryption(subscriber base.DecryptionSubscriber) {
	proxy.decryptionObserver.SubscribeOnAllColumnsDecryption(subscriber)
}

// Unsubscribe a subscriber from all notifications.
func (proxy *PgProxy) Unsubscribe(subscriber base.DecryptionSubscriber) {
	proxy.decryptionObserver.Unsubscribe(subscriber)
}

func (proxy *PgProxy) onColumnDecryption(parentCtx context.Context, i int, data []byte, binaryFormat bool) ([]byte, error) {
	accessContext := base.AccessContextFromContext(parentCtx)
	accessContext.SetColumnInfo(base.NewColumnInfo(i, "", binaryFormat, len(data), 0, 0))
	// create new ctx per column processing
	ctx := base.SetAccessContextToContext(parentCtx, accessContext)
	_, newData, err := proxy.decryptionObserver.OnColumnDecryption(ctx, i, data)
	return newData, err
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
func (proxy *PgProxy) ProxyClientConnection(ctx context.Context, errCh chan<- base.ProxyError) {
	ctx, span := trace.StartSpan(ctx, "ProxyClientConnection")
	defer span.End()
	logger := logging.NewLoggerWithTrace(ctx).WithField("proxy", "client")
	logger.Debugln("ProxyClientConnection")
	writer := bufio.NewWriter(proxy.dbConnection)

	reader := bufio.NewReader(proxy.clientConnection)
	packet, err := NewClientSidePacketHandler(reader, writer, logger)
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlPacketHandlerInitiailization).WithError(err).Errorln("Can't initialize packet handler object")
		errCh <- base.NewClientProxyError(err)
		return
	}
	prometheusLabels := []string{base.DecryptionDBPostgresql}
	// use pointers to function where should be stored some function that should be called if code return error and interrupt loop
	// default value empty func to avoid != nil check
	var spanEndFunc = func() {}
	var timerObserveFunc = func() time.Duration { return 0 }
	for {
		timerObserveFunc()
		packet.Reset()
		spanEndFunc()

		if err = packet.ReadClientPacket(); err != nil {
			if proxy.stopClient {
				proxy.stopClient = false
				proxy.ClientStopResponse <- true
				return
			}
			// log message with debug level because only here we expect and can meet errors with closed connections io.EOF
			logger.WithError(err).Debugln("Can't read packet from client to database")
			errCh <- base.NewClientProxyError(err)
			return
		}
		timer := prometheus.NewTimer(prometheus.ObserverFunc(base.RequestProcessingTimeHistogram.WithLabelValues(prometheusLabels...).Observe))
		timerObserveFunc = timer.ObserveDuration

		packetSpanCtx, packetSpan := trace.StartSpan(ctx, "ProxyClientConnectionLoop")
		spanEndFunc = packetSpan.End

		proxy.dbConnection.SetWriteDeadline(time.Now().Add(network.DefaultNetworkTimeout))

		_, censorSpan := trace.StartSpan(packetSpanCtx, "censor")

		// Massage the packet. This should not normally fail. If it does, the database will not receive the packet.
		censored, err := proxy.handleClientPacket(ctx, packet, logger)
		if err != nil {
			errCh <- base.NewClientProxyError(err)
			return
		}

		censorSpan.End()

		// If the packet has been rejected by AcraCensor, stop here and don't send it to the database.
		// Also, craft and send the client an error so that they know their query has been rejected.
		if censored {
			err := proxy.sendClientError(base.AcraCensorBlockedThisQuery, logger)
			if err != nil {
				errCh <- base.NewClientProxyError(err)
				return
			}
			continue
		}

		// After tha packet has been observed and possibly modified, forward it to the database.
		if err := packet.sendPacket(); err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).
				WithError(err).Errorln("Can't send packet")
			errCh <- base.NewClientProxyError(err)
			return
		}
		// If this is a termination packet, we're done here. Signal EOF and stop the proxy.
		if packet.terminatePacket {
			errCh <- base.NewClientProxyError(err)
			return
		}
	}
}

func (proxy *PgProxy) handleClientPacket(ctx context.Context, packet *PacketHandler, logger *log.Entry) (bool, error) {
	// Let the protocol observer take a look at the packet, keeping note of it.
	err := proxy.protocolState.HandleClientPacket(packet)
	if err != nil {
		return false, err
	}
	switch proxy.protocolState.LastPacketType() {
	case ParseStatementPacket:
		censored, err := proxy.handleQueryPacket(ctx, packet, logger)
		if err != nil || censored {
			return censored, err
		}
		// Register prepared statement, though it can produce an error on the db
		// side. In that case, it should have been removed from the registry,
		// but for now it is not implemented yet. Therefore, connection with a
		// large number of prepared statements with errors tend to leak memory,
		// but on practice it is not that noticeable.
		pendingParse := proxy.protocolState.pendingParse
		if err = proxy.registerPreparedStatement(packet, pendingParse, logger); err != nil {
			return false, err
		}
		err = replaceOIDsInParsePackets(proxy.ctx, packet, pendingParse, logger)
		return false, err
	case SimpleQueryPacket:
		// If that's some sort of a packet with a query inside it,
		// process inline data if necessary and remember the query to handle future response.
		return proxy.handleQueryPacket(ctx, packet, logger)

	case BindStatementPacket:
		// Bound query parameters may contain inline data that we need to process.
		// Also, remember the requested portal name for future data queries.
		return proxy.handleBindPacket(ctx, packet, logger)

	default:
		// Forward all other uninteresting packets to the database without processing.
		return false, nil
	}
}

func (proxy *PgProxy) handleQueryPacket(ctx context.Context, packet *PacketHandler, logger *log.Entry) (bool, error) {
	query := proxy.protocolState.PendingQuery()

	// Log query text -- if and only if we're in debug mode -- without inserted value data.
	// The query can still be sensitive though, so only in debug mode can we do this.
	if logging.GetLogLevel() == logging.LogDebug {
		_, queryWithHiddenValues, _, err := proxy.parser.HandleRawSQLQuery(query.Query())
		if err == sqlparser.ErrQuerySyntaxError {
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
	newQuery, changed, err := proxy.queryObserverManager.OnQuery(ctx, query)
	if err != nil {
		if filesystem.IsKeyReadError(err) {
			return false, err
		}

		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorEncryptQueryData).
			Errorln("Error occurred on query handler")
	}
	if changed {
		packet.ReplaceQuery(newQuery.Query())
	}
	return false, nil
}

func (proxy *PgProxy) handleBindPacket(ctx context.Context, packet *PacketHandler, logger *log.Entry) (bool, error) {
	bind, err := proxy.protocolState.LastBind()
	if err != nil {
		logger.WithError(err).Errorln("Can't get pending Bind packet")
		return false, err
	}
	logger = logger.WithField("portal", bind.PortalName()).WithField("statement", bind.StatementName())
	logger.Debug("Bind packet")
	// There must be previously registered prepared statement with requested name. If there isn't
	// it's likely due to a client error. Print a warning and let the packet through as is.
	// We can't do anything with it and the database should respond with an error.
	registry := proxy.session.PreparedStatementRegistry()
	statement, err := registry.StatementByName(bind.StatementName())
	if err != nil {
		logger.WithError(err).Error("Failed to handle Bind packet: can't find prepared statement")
		return false, nil
	}
	// Now, repackage the parameters for processing... If that fails, let the packet through too.
	parameters, err := bind.GetParameters()
	if err != nil {
		logger.WithError(err).Error("Failed to handle Bind packet: can't extract parameters")
		return false, nil
	}
	// Process parameter values. If we can't -- you guessed it -- leave the packet unchanged.
	// Note that the new parameter set might have different number of items.
	newParameters, changed, err := proxy.queryObserverManager.OnBind(ctx, statement.Query(), parameters)
	if err != nil {
		if filesystem.IsKeyReadError(err) {
			return false, err
		}

		logger.WithError(err).Error("Failed to handle Bind packet")
		return false, nil
	}
	// Finally, if the parameter values have been changed, update the packet.
	// If that fails, send the packet unchanged, as usual.
	if changed {
		bind.SetParameters(newParameters)
		err = packet.ReplaceBind(bind)
		if err != nil {
			logger.WithError(err).Error("Failed to update Bind packet")
		}
		return false, nil
	}
	return false, nil
}

func (proxy *PgProxy) sendClientError(msg string, logger *log.Entry) error {
	errorMessage, err := NewPgError(msg)
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantGenerateErrorPacket).
			WithError(err).Errorln("Can't create PostgreSQL error message")
		return err
	}
	n, err := proxy.clientConnection.Write(errorMessage)
	if err := base.CheckReadWrite(n, len(errorMessage), err); err != nil {
		return err
	}
	n, err = proxy.clientConnection.Write(ReadyForQuery)
	if err := base.CheckReadWrite(n, len(ReadyForQuery), err); err != nil {
		return err
	}
	return nil
}

// stopProxyClientConnection sends a signal to a client thread to stop. Returns error in
// case of an error or timeout. Is used to stop and reload client with TLS
func (proxy *PgProxy) stopProxyClientConnection(logger *log.Entry) error {
	proxy.stopClient = true
	// stop reading from client in goroutine
	if err := proxy.clientConnection.SetDeadline(time.Now()); err != nil {
		logger.
			WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantSetDeadlineToClientConnection).
			Errorln("Can't set deadline")
		return err
	}

	select {
	case <-proxy.ClientStopResponse:
	case <-time.NewTimer(ClientStopTimeout).C:
		logger.
			// TODO: which event code
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
			Errorln("Can't stop background goroutine")
		return errors.New("can't stop background goroutine")
	}

	// Reset the deadline
	// From the https://pkg.go.dev/net#Conn:
	//
	//   A zero value for t means I/O operations will not time out.
	//
	if err := proxy.clientConnection.SetDeadline(time.Time{}); err != nil {
		logger.
			WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantSetDeadlineToClientConnection).
			Errorln("Can't set deadline")
		return err
	}
	logger.Debugln("Stop client connection")
	return nil
}

// handleSSLRequest return wrapped with tls (client's, db's connections, nil) or (nil, nil, error)
func (proxy *PgProxy) handleSSLRequest(packet *PacketHandler, logger *log.Entry) (net.Conn, net.Conn, error) {
	// if server allow SSLRequest than we wrap our connections with tls
	if proxy.setting.TLSConnectionWrapper() == nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).Errorln("To support TLS connections you must pass TLS key and certificate for AcraServer that will be used " +
			"for connections AcraServer->Database and CA certificate which will be used to verify certificate " +
			"from database")
		return nil, nil, network.ErrEmptyTLSConfig
	}
	logger.Debugln("Start tls proxy")
	if err := proxy.stopProxyClientConnection(logger); err != nil {
		return nil, nil, err
	}
	logger.Debugln("Init tls with client")
	// send server's response only after successful interrupting background goroutine that process client's connection
	// to take control over connection and avoid two places that communicate with one connection
	if err := packet.sendMessageType(); err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
			Errorln("Can't send ssl allow packet")
		return nil, nil, err
	}
	// convert to tls connection
	tlsClientConnection, clientID, err := proxy.setting.TLSConnectionWrapper().WrapClientConnection(proxy.ctx, proxy.clientConnection)
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
			Errorln("Error in tls handshake with client")
		var crlErr *network.CRLError
		if network.IsClientBadRecordMacError(err) {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
				Infoln(network.ClientSideBadMacErrorSuggestion)
		} else if network.IsClientUnknownCAError(err) {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
				Infoln(network.ClientSideUnknownCAErrorSuggestion)
		} else if network.IsMissingClientCertificate(err) {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
				Infoln(network.ClientSideNoCertificateErrorSuggestion)
		} else if errors.As(err, &crlErr) {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
				Infoln(network.CRLCheckErrorSuggestion)
		}
		return nil, nil, err
	}
	logger.WithField("use_client_id", proxy.setting.TLSConnectionWrapper().UseConnectionClientID()).Infoln("TLS connection to db")
	if proxy.setting.TLSConnectionWrapper().UseConnectionClientID() {
		logger.WithField("client_id", string(clientID)).Infoln("Set new clientID")
		proxy.clientIDObserverManager.OnNewClientID(clientID)
	}
	logger.Debugln("Init tls with db")
	dbTLSConnection, err := proxy.setting.TLSConnectionWrapper().WrapDBConnection(proxy.ctx, proxy.dbConnection)
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
			Errorln("Can't initialize tls connection with db")
		var crlErr *network.CRLError
		if network.IsSNIError(err) {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
				Infoln(network.DatabaseSideSNIErrorSuggestion)
		} else if network.IsDatabaseUnknownCAError(err) {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
				Infoln(network.DatabaseSideUnknownCAErrorSuggestions)
		} else if errors.As(err, &crlErr) {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
				Infoln(network.CRLCheckErrorSuggestion)
		}
		return nil, nil, err
	}
	return tlsClientConnection, dbTLSConnection, nil
}

// ProxyDatabaseConnection process data rows from database
func (proxy *PgProxy) ProxyDatabaseConnection(ctx context.Context, errCh chan<- base.ProxyError) {
	ctx, span := trace.StartSpan(ctx, "PgDecryptStream")
	defer span.End()
	logger := logging.NewLoggerWithTrace(ctx).WithField("proxy", "server")
	logger.Debugln("Pg db proxy")
	// use buffered writer because we generate response by parts
	writer := bufio.NewWriter(proxy.clientConnection)

	reader := bufio.NewReader(proxy.dbConnection)
	packetHandler, err := NewDbSidePacketHandler(reader, writer, logger)
	if err != nil {
		errCh <- base.NewDBProxyError(err)
		return
	}

	var state databaseHandlerState = stateFirstPacket

	// use pointer to function where should be stored some function that should be called if code return error and interrupt loop
	// default value empty func to avoid != nil check
	var endLoopSpanFunc = func() {}
	var packetCtx context.Context
	var packetSpan *trace.Span
	for {
		// end span of previous iteration
		endLoopSpanFunc()

		packetHandler.Reset()
		switch state {
		case stateServe:
			// General response, which we handle and forward to the client
			if err = packetHandler.ReadPacket(); err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).WithError(err).Debugln("Can't read packet")
				errCh <- base.NewDBProxyError(err)
				return
			}
			timer := prometheus.NewTimer(prometheus.ObserverFunc(base.ResponseProcessingTimeHistogram.WithLabelValues(base.DecryptionDBPostgresql).Observe))
			packetCtx, packetSpan = trace.StartSpan(ctx, "PgDecryptStreamLoop")
			endLoopSpanFunc = packetSpan.End

			proxy.clientConnection.SetWriteDeadline(time.Now().Add(network.DefaultNetworkTimeout))

			// Massage the packet. This should not normally fail. If it does, the client will not receive the packet.
			err := proxy.handleDatabasePacket(packetCtx, packetHandler, logger)
			if decryptionError, ok := err.(*base.EncodingError); ok {
				if err = proxy.sendClientError(decryptionError.Error(), logger); err != nil {
					logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).
						WithError(err).Errorln("Can't send packet")
					errCh <- base.NewDBProxyError(err)
					return
				}
				// We need to flush out the rest of the response
				state = stateSkipResponse
				continue
			}

			if err != nil {
				errCh <- base.NewDBProxyError(err)
				return
			}

			// After tha packet has been observed and possibly modified, forward it to the client.
			if err = packetHandler.sendPacket(); err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).
					WithError(err).Errorln("Can't send packet")
				errCh <- base.NewDBProxyError(err)
				return
			}
			timer.ObserveDuration()

		case stateFirstPacket:
			// Startup response, which contains only one byte. It's special,
			// because it can request switching to TLS.

			_, packetSpan = trace.StartSpan(ctx, "PgDecryptStreamLoop")
			endLoopSpanFunc = packetSpan.End

			packetSpan.AddAttributes(trace.BoolAttribute("startup", true))
			// https://www.postgresql.org/docs/9.1/static/protocol-flow.html#AEN92112
			// we should know that we shouldn't read anymore bytes
			// first response from server may contain only one byte of response on SSLRequest
			state = stateServe
			logger.Debugln("Read startup message")
			if err = packetHandler.readMessageType(); err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).WithError(err).Debugln("Can't read first message type")
				errCh <- base.NewDBProxyError(err)
				return
			}
			timer := prometheus.NewTimer(prometheus.ObserverFunc(base.ResponseProcessingTimeHistogram.WithLabelValues(base.DecryptionDBPostgresql).Observe))

			switch {
			case packetHandler.IsSSLRequestDeny():
				logger.Debugln("Deny ssl request")
				// In case of deny ssl, the client can send plain startup message
				// again. To handle this, we reload client thread to reset the state
				if err := proxy.stopProxyClientConnection(logger); err != nil {
					errCh <- base.NewDBProxyError(err)
					return
				}
				go proxy.ProxyClientConnection(ctx, errCh)

				if err = packetHandler.sendMessageType(); err != nil {
					errCh <- base.NewDBProxyError(err)
					return
				}
				timer.ObserveDuration()

			case packetHandler.IsSSLRequestAllowed():
				logger.Debugln("SSL allow")

				tlsClientConnection, dbTLSConnection, err := proxy.handleSSLRequest(packetHandler, logger)
				if err != nil {
					logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).WithError(err).Errorln("Can't process SSL request")
					errCh <- base.NewDBProxyError(err)
					return
				}
				proxy.clientConnection = tlsClientConnection
				proxy.dbConnection = dbTLSConnection
				// restart proxing client's requests
				go proxy.ProxyClientConnection(ctx, errCh)
				reader = bufio.NewReader(dbTLSConnection)
				writer = bufio.NewWriter(tlsClientConnection)

				packetHandler.reader = reader
				packetHandler.writer = writer
				packetHandler.Reset()
				timer.ObserveDuration()

			default:
				logger.Debugln("Non-ssl request start up message")
				// if it is not ssl request than we just forward it to client
				if err = packetHandler.readData(true); err != nil {
					logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).WithError(err).Errorln("Can't read data of packet")
					errCh <- base.NewDBProxyError(err)
					return
				}
				if err = packetHandler.sendPacket(); err != nil {
					logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).WithError(err).Errorln("Can't forward first packet")
					errCh <- base.NewDBProxyError(err)
					return
				}
				timer.ObserveDuration()
			}
		case stateSkipResponse:
			endLoopSpanFunc = func() {}
			if err = packetHandler.ReadPacket(); err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).
					WithError(err).
					Debugln("Can't read packet")
				errCh <- base.NewDBProxyError(err)
				return
			}
			last := packetHandler.IsReadyForQuery()
			if last {
				state = stateServe
				// Process the ReadyForQuery packet to reset the state of the
				// protocol and do necessary cleanup
				if err := proxy.handleDatabasePacket(packetCtx, packetHandler, logger); err != nil {
					errCh <- base.NewDBProxyError(err)
					return
				}
			}
			logger.WithField("last", last).Debugln("Skipping the packet")
		}
	}
}

func (proxy *PgProxy) handleDatabasePacket(ctx context.Context, packet *PacketHandler, logger *log.Entry) error {
	// reset previously matched zone
	base.AccessContextFromContext(ctx).SetZoneID(nil)
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
		log.WithField("parse", proxy.protocolState.pendingParse).Debugln("ParseComplete")
		proxy.protocolState.forgetPendingParse()
		return nil

	case BindCompletePacket:
		// Previously requested cursor has been confirmed by the database, register it.
		bindPacket, err := proxy.protocolState.PendingBind()
		if err != nil {
			logger.WithError(err).Errorln("Can't get pending Bind packet")
			return err
		}
		defer func() {
			if err := proxy.protocolState.forgetPendingBind(); err != nil {
				logger.WithError(err).Errorln("Can't forget pending Bind packet")
			}
		}()
		return proxy.registerCursor(bindPacket, logger)
	case RowDescriptionPacket:
		return proxy.handleRowDescription(ctx, packet, logger)

	case ParameterDescriptionPacket:
		return proxy.handleParameterDescription(ctx, packet, logger)

	case ReadyForQueryPacket:
		logger.Debugln("ReadyForQueryPacket")
		encryptor.DeletePlaceholderSettingsFromClientSession(proxy.session)
		return nil

	default:
		// Forward all other uninteresting packets to the client without processing.
		return nil
	}
}

func (proxy *PgProxy) handleParameterDescription(ctx context.Context, packet *PacketHandler, logger *log.Entry) error {
	clientSession := base.ClientSessionFromContext(ctx)
	if clientSession == nil {
		logger.Warningln("ParameterDescription packet without ClientSession in context")
		return nil
	}
	items := encryptor.PlaceholderSettingsFromClientSession(clientSession)
	if items == nil {
		logger.Debugln("ParameterDescription packet without registered recognized encryption settings")
		return nil
	}
	parameterDescription, err := packet.GetParameterDescriptionData()
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDBProtocolError).
			WithError(err).
			Errorln("Can't parse ParameterDescription packet")
		return nil
	}
	changed := false
	for i := 0; i < len(parameterDescription.ParameterOIDs); i++ {
		setting := items[i]
		if setting == nil {
			continue
		}
		if config.HasTypeAwareSupport(setting) {
			newOID, ok := mapEncryptedTypeToOID(setting.GetEncryptedDataType())
			if ok {
				parameterDescription.ParameterOIDs[i] = newOID
				changed = true
			}
		}
	}
	if changed {
		// 5 is MessageType[1] + PacketLength[4] + PacketPayload
		newParameterDescription := make([]byte, 0, 5+packet.descriptionBuf.Len())
		newParameterDescription = parameterDescription.Encode(newParameterDescription)
		packet.descriptionBuf.Reset()
		packet.descriptionBuf.Write(newParameterDescription[5:])
	}
	return nil
}

func (proxy *PgProxy) handleRowDescription(ctx context.Context, packet *PacketHandler, logger *log.Entry) error {
	clientSession := base.ClientSessionFromContext(ctx)
	if clientSession == nil {
		logger.Warningln("RowDescription packet without ClientSession in context")
		return nil
	}
	items := encryptor.QueryDataItemsFromClientSession(clientSession)
	if items == nil {
		logger.Debugln("RowDescription packet without registered recognized encryption settings")
		return nil
	}
	rowDescription, err := packet.GetRowDescriptionData()
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDBProtocolError).
			WithError(err).
			Errorln("Can't parse RowDescription packet")
		return nil
	}
	if len(items) != len(rowDescription.Fields) {
		log.Errorln("Column count in RowDescription packet not same as parsed query count of columns")
		return nil
	}
	changed := false
	for i := 0; i < len(rowDescription.Fields); i++ {
		setting := items[i]
		if setting == nil {
			continue
		}
		if config.HasTypeAwareSupport(setting.Setting()) {
			newOID, ok := mapEncryptedTypeToOID(setting.Setting().GetEncryptedDataType())
			if ok {
				rowDescription.Fields[i].DataTypeOID = newOID
				changed = true
			}
		}
	}
	if changed {
		// 5 is MessageType[1] + PacketLength[4] + PacketPayload
		newRowDescription := make([]byte, 0, 5+packet.descriptionBuf.Len())
		newRowDescription = rowDescription.Encode(newRowDescription)
		packet.descriptionBuf.Reset()
		packet.descriptionBuf.Write(newRowDescription[5:])
	}
	return nil
}

func (proxy *PgProxy) handleQueryDataPacket(ctx context.Context, packet *PacketHandler, logger *log.Entry) error {
	logger.Debugln("Matched data row packet")
	// by default it's text format
	columnFormats := []uint16{uint16(base.TextFormat)}
	if bindPacket, err := proxy.protocolState.PendingBind(); err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantParseColumnsDescription).
			WithError(err).Errorln("Can't get pending Bind packet")
		return err
	} else if bindPacket != nil {
		columnFormats, err = bindPacket.GetResultFormats()
		if err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantParseColumnsDescription).
				WithError(err).Errorln("Can't get result formats from Bind packet")
			return err
		}
	}
	if err := packet.parseColumns(columnFormats); err != nil {
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
		// default values Text
		format := 0
		pendingBind, err := proxy.protocolState.pendingPackets.GetPendingPacket(&BindPacket{})
		if err != nil {
			panic(err)
		}
		if pendingBind != nil {
			boundFormat, err := GetParameterFormatByIndex(i, pendingBind.(*BindPacket).resultFormats)
			if err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantParseColumnsDescription).
					WithError(err).Errorln("Can't get format for column")
				return err
			}
			format = int(boundFormat)
		}
		logger.WithField("data_length", len(column.GetData())).WithField("column_index", i).Debugln("Process columns data")
		newData, err := proxy.onColumnDecryption(ctx, i, column.GetData(), format == dataFormatBinary)
		if err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
				WithError(err).Errorln("Error on column data processing")
			return err
		}
		column.SetData(newData)
	}
	// After we're done processing the columns, update the actual packet data from them
	queryDataItems := make([]*encryptor.QueryDataItem, packet.columnCount)
	clientSession := base.ClientSessionFromContext(ctx)
	if clientSession != nil {
		queryDataItems = encryptor.QueryDataItemsFromClientSession(clientSession)
	}
	packet.updateDataFromColumns(queryDataItems)
	return nil
}

func (proxy *PgProxy) registerPreparedStatement(packet *PacketHandler, preparedStatement *ParsePacket, logger *log.Entry) error {
	name := preparedStatement.Name()
	queryText := preparedStatement.QueryString()
	// This should be always successful since the database filters invalid queries.
	query, err := proxy.parser.Parse(queryText)
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

// replaceOIDsInParsePackets replaces OID of parameters that could be specified
// in a parse packet into BYTEA. That's because all encrypted data is stored
// as a BYTEA in the postgres. Only during the insertion/selection we do
// encryption/decryption and substitution of the correct type.
func replaceOIDsInParsePackets(ctx context.Context, packet *PacketHandler, preparedStatement *ParsePacket, logger *log.Entry) error {
	if len(preparedStatement.params) == 0 {
		return nil
	}
	clientSession := base.ClientSessionFromContext(ctx)
	if clientSession == nil {
		logger.Warningln("ParsePacket packet without ClientSession in context")
		return nil
	}
	items := encryptor.PlaceholderSettingsFromClientSession(clientSession)
	if items == nil {
		logger.Debugln("ParsePacket packet without registered recognized encryption settings")
		return nil
	}
	changed := false
	for i := range preparedStatement.params {
		setting := items[i]
		if setting == nil {
			continue
		}
		if config.HasTypeAwareSupport(setting) {
			logger.WithField("field", setting.ColumnName()).Debugln("Change parameter types for ParsePacket")
			binary.BigEndian.PutUint32(preparedStatement.params[i], pgtype.ByteaOID)
			changed = true
		}
	}
	if changed {
		return packet.SetParsePacket(preparedStatement)
	}
	return nil
}

func (proxy *PgProxy) registerCursor(bindPacket *BindPacket, logger *log.Entry) error {
	registry := proxy.session.PreparedStatementRegistry()
	// There should be a statement with the specified name, the database confirmed it.
	statementName := bindPacket.StatementName()
	preparedStatement, err := registry.StatementByName(statementName)
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("Failed to add cursor")
		return err
	}
	// Cursors are called portals in PostgreSQL.
	cursorName := bindPacket.PortalName()
	cursor := NewPortal(cursorName, preparedStatement)
	err = registry.AddCursor(cursor)
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("Failed to add cursor")
		return err
	}
	logger.WithField("cursor_name", cursorName).WithField("prepared_name", statementName).
		Debug("Registered new cursor")
	return nil
}

// AddClientIDObserver subscribe new observer for clientID changes
func (proxy *PgProxy) AddClientIDObserver(observer base.ClientIDObserver) {
	proxy.clientIDObserverManager.AddClientIDObserver(observer)
}
