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
	"go.opencensus.io/trace"
	"io"
	"net"
	"time"

	"github.com/cossacklabs/acra/acra-censor"
	"github.com/cossacklabs/acra/acra-censor/common"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
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

// PgSQL constant sizes and types.
const (
	// DataRowLengthBufSize each postgresql packet contain 4 byte that store length of message contents in bytes, including self
	DataRowLengthBufSize = 4
	// random chosen
	OutputDefaultSize = 1024
	// https://www.postgresql.org/docs/9.4/static/protocol-message-formats.html
	DataRowMessageType byte = 'D'
	QueryMessageType   byte = 'Q'
	ParseMessageType   byte = 'P'
	TLSTimeout              = time.Second * 2
)

// PgProxy represents PgSQL database connection between client and database with TLS support
type PgProxy struct {
	clientConnection     net.Conn
	dbConnection         net.Conn
	TLSCh                chan bool
	ctx                  context.Context
	queryObserverManager base.QueryObserverManager
	tlsConfig            *tls.Config
	censor               acracensor.AcraCensorInterface
	decryptor            base.Decryptor
	tlsSwitch            bool
}

// NewPgProxy returns new PgProxy
func NewPgProxy(ctx context.Context, decryptor base.Decryptor, dbConnection, clientConnection net.Conn, tlsConfig *tls.Config, censor acracensor.AcraCensorInterface) (*PgProxy, error) {
	observerManager, err := base.NewArrayQueryObserverableManager(ctx)
	if err != nil {
		return nil, err
	}
	return &PgProxy{
		clientConnection:     clientConnection,
		dbConnection:         dbConnection,
		TLSCh:                make(chan bool),
		ctx:                  ctx,
		queryObserverManager: observerManager,
		tlsConfig:            tlsConfig,
		censor:               censor,
		decryptor:            decryptor,
	}, nil
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
			// log message with debug level because onlt here we expect and can meet errors with closed connections .ioEOF
			logger.WithError(err).Debugln("Can't read packet from client to database")
			errCh <- err
			return
		}
		proxy.dbConnection.SetWriteDeadline(time.Now().Add(network.DefaultNetworkTimeout))
		// we are interested only in requests that contains sql queries
		if !(packet.IsSimpleQuery() || packet.IsParse()) {
			if err = packet.sendPacket(); err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).WithError(err).Errorln("Can't forward packet to db")
				errCh <- err
				return
			}
			if packet.terminatePacket {
				errCh <- io.EOF
				return
			}
			continue
		}
		_, censorSpan := trace.StartSpan(packetSpanCtx, "censor")
		var query string
		if packet.IsSimpleQuery() {
			query, err = packet.GetSimpleQuery()
			if err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantExtractQueryString).WithError(err).Errorln("Can't fetch query string from Query packet")
				errCh <- err
				return
			}
		} else if packet.IsParse() {
			query, err = packet.GetParseQuery()
			if err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantExtractQueryString).WithError(err).Errorln("Can't fetch query string from Parse packet")
				errCh <- err
				return
			}
		} else {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlUnexpectedPacket).Errorf("Unhandled message type <%v>", packet.messageType[0])
			errCh <- errors.New("unhandled message type")
			return
		}

		// log query with hidden values for debug mode
		if logging.GetLogLevel() == logging.LogDebug {
			_, queryWithHiddenValues, _, err := common.HandleRawSQLQuery(query)
			if err == common.ErrQuerySyntaxError {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).WithError(err).Debugf("Parsing error on query: %s", queryWithHiddenValues)
			} else {
				logger.WithField("sql", queryWithHiddenValues).Debugln("New query")
			}
		}

		if censorErr := proxy.censor.HandleQuery(query); censorErr != nil {
			censorSpan.End()
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).WithError(censorErr).Errorln("AcraCensor blocked query")
			errorMessage, err := NewPgError("AcraCensor blocked this query")
			if err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantGenerateErrorPacket).WithError(err).Errorln("Can't create PostgreSQL error message")
				errCh <- err
				return
			}
			n, err := proxy.clientConnection.Write(errorMessage)
			if err := base.CheckReadWrite(n, len(errorMessage), err); err != nil {
				errCh <- err
				return
			}
			n, err = proxy.clientConnection.Write(ReadyForQueryPacket)
			if err := base.CheckReadWrite(n, len(ReadyForQueryPacket), err); err != nil {
				errCh <- err
				return
			}
			continue
		}

		newQuery, changed, err := proxy.queryObserverManager.OnQuery(base.NewOnQueryObjectFromQuery(query))
		if err != nil {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorEncryptQueryData).Errorln("Error occurred on query handler")
		}
		if changed {
			packet.ReplaceQuery(newQuery.Query())
		}

		censorSpan.End()

		if err := packet.sendPacket(); err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).WithError(err).Errorln("Can't send packet")
			errCh <- err
			return
		}
	}
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
			currentIndex += index
			if err := checkWholePoisonRecord(block[currentIndex:], decryptor, logger); err != nil {
				return err
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
	skippedBegin, err := decryptor.SkipBeginInBlock(block)
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantSkipBeginInBlock).WithError(err).Debugln("Can't skip begin tag for poison record check")
		return nil
	}
	poisoned, checkErr := decryptor.CheckPoisonRecord(bytes.NewReader(skippedBegin))
	if innerErr := handlePoisonCheckResult(decryptor, poisoned, checkErr, logger); err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(innerErr).Errorln("Error on poison record check")
		return innerErr
	}
	return checkErr
}

// processWholeBlockDecryption try to decrypt data of column as whole AcraStruct and replace with decrypted data on success
func (proxy *PgProxy) processWholeBlockDecryption(ctx context.Context, packet *PacketHandler, column *ColumnData, decryptor base.Decryptor, logger *log.Entry) error {
	span := trace.FromContext(ctx)
	decryptor.Reset()
	decrypted, err := decryptor.DecryptBlock(column.Data)
	if err == errPlainData {
		// it's not AcraStruct
		return nil
	}
	if err != nil {
		span.AddAttributes(trace.BoolAttribute("failed_decryption", true))
		// check poison records on failed decryption
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).WithError(err).Warningln("Can't decrypt AcraStruct")
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
		if decryptor.IsPoisonRecordCheckOn() {
			decryptor.Reset()
			if err := checkWholePoisonRecord(column.Data, decryptor, logger); err != nil {
				return err
			}
		}
		return nil
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
	column.SetData(decrypted)
	return nil
}

// handleSSLRequest return wrapped with tls (client's, db's connections, nil) or (nil, nil, error)
func (proxy *PgProxy) handleSSLRequest(packet *PacketHandler, tlsConfig *tls.Config, logger *log.Entry) (net.Conn, net.Conn, error) {
	// if server allow SSLRequest than we wrap our connections with tls
	if tlsConfig == nil {
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
	tlsClientConnection := tls.Server(proxy.clientConnection, tlsConfig)

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
	dbTLSConnection := tls.Client(proxy.dbConnection, tlsConfig)
	if err := dbTLSConnection.Handshake(); err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
			Errorln("Can't initialize tls connection with db")
		return nil, nil, err
	}
	return tlsClientConnection, dbTLSConnection, nil
}

func (proxy *PgProxy) processInlineBlockDecryption(ctx context.Context, packet *PacketHandler, column *ColumnData, decryptor base.Decryptor, logger *log.Entry) error {
	span := trace.FromContext(ctx)
	// inline mode
	currentIndex := 0
	endIndex := column.Length()
	outputBlock := bytes.NewBuffer(make([]byte, 0, column.Length()))
	hasDecryptedData := false
	for {
		// search AcraStruct's begin tags through all block of data and try to decrypt
		beginTagIndex, tagLength := decryptor.BeginTagIndex(column.Data[currentIndex:endIndex])
		if beginTagIndex == utils.NotFound {
			// no AcraStructs in column decryptedData
			break
		}
		// convert to absolute index
		beginTagIndex += currentIndex
		// write data before start of AcraStruct
		outputBlock.Write(column.Data[currentIndex:beginTagIndex])
		currentIndex = beginTagIndex

		key, err := decryptor.GetPrivateKey()
		if err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadKeys).WithError(err).Warningln("Can't read private key for matched client_id/zone_id")
			if decryptor.IsPoisonRecordCheckOn() {
				logger.Infoln("Check poison records")
				blockReader := bytes.NewReader(column.Data[beginTagIndex+tagLength:])
				poisoned, err := decryptor.CheckPoisonRecord(blockReader)
				if err = handlePoisonCheckResult(decryptor, poisoned, err, logger); err != nil {
					return err
				}
			}
			currentIndex++
			continue
		}
		blockReader := bytes.NewReader(column.Data[beginTagIndex+tagLength:])
		symKey, _, err := decryptor.ReadSymmetricKey(key, blockReader)
		if err != nil {
			span.AddAttributes(trace.BoolAttribute("failed_decryption", true))
			base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptSymmetricKey).Warningln("Can't unwrap symmetric key")
			if decryptor.IsPoisonRecordCheckOn() {
				logger.Infoln("Check poison records")
				blockReader = bytes.NewReader(column.Data[beginTagIndex+tagLength:])
				poisoned, err := decryptor.CheckPoisonRecord(blockReader)
				if err = handlePoisonCheckResult(decryptor, poisoned, err, logger); err != nil {
					return err
				}
			}

			// write current read byte to not process him in next iteration
			outputBlock.Write([]byte{column.Data[currentIndex]})
			currentIndex++
			continue
		}
		decryptedData, err := decryptor.ReadData(symKey, decryptor.GetMatchedZoneID(), blockReader)
		if err != nil {
			span.AddAttributes(trace.BoolAttribute("failed_decryption", true))
			base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).WithError(err).Warningln("Can't decrypt data with unwrapped symmetric key")
			// write current read byte to not process him in next iteration
			outputBlock.Write([]byte{column.Data[currentIndex]})
			currentIndex++
			continue
		}
		logger.Infoln("Decrypted AcraStruct")
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
		outputBlock.Write(decryptedData)
		currentIndex += tagLength + (len(column.Data[beginTagIndex+tagLength:]) - blockReader.Len())
		hasDecryptedData = true
	}
	if hasDecryptedData {
		logger.WithFields(log.Fields{"old_size": column.Length(), "new_size": outputBlock.Len()}).Debugln("Result was changed")
		column.SetData(outputBlock.Bytes())
		decryptor.ResetZoneMatch()
		decryptor.Reset()
	} else {
		logger.Debugln("Result was not changed")
	}
	return nil
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
				tlsClientConnection, dbTLSConnection, err := proxy.handleSSLRequest(packetHandler, proxy.tlsConfig, logger)
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

		if !packetHandler.IsDataRow() {
			if err = packetHandler.sendPacket(); err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).WithError(err).Errorln("Can't forward packet")
				errCh <- err
				return
			}
			timer.ObserveDuration()
			continue
		}

		logger.Debugln("Matched data row packet")
		if err = packetHandler.parseColumns(); err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlCantParseColumnsDescription).WithError(err).Errorln("Can't parse columns in packet")
			errCh <- err
			return
		}

		if packetHandler.columnCount == 0 {
			if err = packetHandler.sendPacket(); err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).WithError(err).Errorln("Can't send packet on column count 0")
				errCh <- err
				return
			}
			timer.ObserveDuration()
			continue
		}

		logger.Debugf("Process columns data")
		for i := 0; i < packetHandler.columnCount; i++ {
			column := packetHandler.Columns[i]
			if column.IsNull() {
				continue
			}
			// try to skip small piece of data that can't be valuable for us
			if (proxy.decryptor.IsWithZone() && column.Length() >= zone.ZoneIDBlockLength) || column.Length() >= base.GetMinAcraStructLength() {
				proxy.decryptor.Reset()
				packetSpan.AddAttributes(trace.BoolAttribute("decryption", true))

				// Zone anyway should be passed as whole block
				// so try to match before any operations if we process with ZoneMode on
				if proxy.decryptor.IsWithZone() && !proxy.decryptor.IsMatchedZone() {
					packetSpan.AddAttributes(trace.BoolAttribute("match_zone", true))
					// try to match zone
					proxy.decryptor.MatchZoneBlock(column.Data)
					if proxy.decryptor.IsWholeMatch() {
						// check that it's not poison record
						err = checkWholePoisonRecord(column.Data, proxy.decryptor, logger)
					} else {
						// check that it's not poison record
						err = checkInlinePoisonRecordInBlock(column.Data, proxy.decryptor, logger)
					}

					if err != nil {
						logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(err).Errorln("Can't check poison record in block")
						errCh <- err
						return
					}
					continue
				}

				// create temporary logger to log related zone_id in flow of decryption
				// client_id set on higher level on start of processing connection
				decryptionLogger := logger.WithField("zone_id", string(proxy.decryptor.GetMatchedZoneID()))

				if proxy.decryptor.IsWholeMatch() {
					err = proxy.processWholeBlockDecryption(packetCtx, packetHandler, column, proxy.decryptor, decryptionLogger)
					if err != nil {
						decryptionLogger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).WithError(err).Errorln("Can't process whole block")
						errCh <- err
						return
					}
				} else {
					err = proxy.processInlineBlockDecryption(packetCtx, packetHandler, column, proxy.decryptor, decryptionLogger)
					if err != nil {
						decryptionLogger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).WithError(err).Errorln("Can't process block with inline mode")
						errCh <- err
						return
					}
				}
			} else {
				logger.Debugln("Skip decryption because length of block too small for ZoneId or AcraStruct")
			}
		}
		packetHandler.updateDataFromColumns()
		if err = packetHandler.sendPacket(); err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).WithError(err).Errorln("Can't send packet")
			errCh <- err
			return
		}
		proxy.decryptor.Reset()
		proxy.decryptor.ResetZoneMatch()
		timer.ObserveDuration()
	}
}
