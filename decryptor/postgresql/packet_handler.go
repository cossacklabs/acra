package postgresql

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
)

// PacketHandler hold state of postgresql packet and process data rows
// every postgresql packet (except first packet Startup/SSLRequest) has struct as like
// MessageType[1] + PacketLength[4] + PacketData[N] where numbers are size in bytes and N depends from value in PacketLength
type PacketHandler struct {
	messageType          [1]byte
	descriptionLengthBuf []byte
	descriptionBuf       *bytes.Buffer

	columnCount     int
	dataLength      int
	reader          io.Reader
	writer          *bufio.Writer
	logger          *logrus.Entry
	Columns         []*ColumnData
	terminatePacket bool

	// Flag which is true, if one of the startup messages is received (either
	// StartupMessage or SSLRequest).
	// Is used to distinguish which message we parse: startup or general,
	// because due to historical reasons, they have different format.
	//
	// In te db-dedicated code serves as indicator, whether we expect startup
	// response or general response.
	started bool
}

// NewClientSidePacketHandler return new PacketHandler with initialized own logger for client's packets
func NewClientSidePacketHandler(reader io.Reader, writer *bufio.Writer, logger *logrus.Entry) (*PacketHandler, error) {
	return newPacketHandlerWithLogger(reader, writer, logger.WithField("proxy", "client"))
}

// NewDbSidePacketHandler return new PacketHandler with initialized own logger for databases's packets
func NewDbSidePacketHandler(reader io.Reader, writer *bufio.Writer, logger *logrus.Entry) (*PacketHandler, error) {
	return newPacketHandlerWithLogger(reader, writer, logger.WithField("proxy", "server"))
}

// newPacketHandlerWithLogger return new PacketHandler with specific logger
func newPacketHandlerWithLogger(reader io.Reader, writer *bufio.Writer, logger *logrus.Entry) (*PacketHandler, error) {
	return &PacketHandler{
		descriptionBuf:       bytes.NewBuffer(make([]byte, 0, OutputDefaultSize)),
		descriptionLengthBuf: make([]byte, 4),
		reader:               reader,
		writer:               writer,
		logger:               logger,
		terminatePacket:      false,
	}, nil
}

// updatePacketLength update buffer of packet length and set correct size and include size buf itself
func (packet *PacketHandler) updatePacketLength(newLength int) {
	// update packet size
	binary.BigEndian.PutUint32(packet.descriptionLengthBuf[:], uint32(newLength+DataRowLengthBufSize))
}

// updateDataFromColumns check that any column's data was changed and update packet length and data block with new data
func (packet *PacketHandler) updateDataFromColumns() {
	columnsDataChanged := false
	// check is any column was changed
	for i := 0; i < packet.columnCount; i++ {
		if packet.Columns[i].changed {
			columnsDataChanged = true
			break
		}
	}
	if columnsDataChanged {
		// column length buffer wasn't included to column length value and should be accumulated too
		// + 2 is column count buffer
		newDataLength := packet.columnCount*4 + 2
		for i := 0; i < packet.columnCount; i++ {
			newDataLength += packet.Columns[i].Length()
		}
		packet.descriptionBuf.Reset()
		packet.descriptionBuf.Grow(newDataLength)

		columnCountBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(columnCountBuf, uint16(packet.columnCount))
		packet.descriptionBuf.Write(columnCountBuf)

		for i := 0; i < packet.columnCount; i++ {
			packet.descriptionBuf.Write(packet.Columns[i].LengthBuf[:])
			if !packet.Columns[i].IsNull() {
				packet.descriptionBuf.Write(packet.Columns[i].data.Encoded())
			}
		}
		packet.updatePacketLength(newDataLength)
	}
}

// sendPacket marshal packet and send it with writer
func (packet *PacketHandler) sendPacket() error {
	data, err := packet.Marshal()
	if err != nil {
		packet.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantSerializePostgresqlPacket).WithError(err).Errorln("Can't marshal packet")
		return err
	}
	// anyway try to write data that was marshaled even if not full

	if _, err := packet.writer.Write(data); err != nil {
		packet.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).WithError(err).Warningln("Can't dump marshaled packet")
		return err
	}
	if err := packet.writer.Flush(); err != nil {
		packet.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkFlush).WithError(err).Warningln("Can't flush writer")
		return err
	}
	return nil
}

// sendMessageType send and flush messageType buffer
func (packet *PacketHandler) sendMessageType() error {
	n, err := packet.writer.Write(packet.messageType[:])
	if err2 := base.CheckReadWrite(n, 1, err); err2 != nil {
		return err2
	}
	if err := packet.writer.Flush(); err != nil {
		packet.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkFlush).WithError(err).Warningln("Can't flush writer")
		return err
	}
	return nil
}

// ColumnData hold column length and data
type ColumnData struct {
	LengthBuf [4]byte
	data      *utils.DecodedData
	changed   bool
	isNull    bool
}

// GetData return raw data, decoded from db format to binary
func (column *ColumnData) GetData() []byte {
	return column.data.Data()
}

// Length return column length converted from LengthBuf
func (column *ColumnData) Length() int {
	if column.isNull {
		return 0
	}
	return int(binary.BigEndian.Uint32(column.LengthBuf[:]))
}

// IsNull return true if column has null value
func (column *ColumnData) IsNull() bool {
	return column.isNull
}

// ReadLength of column
func (column *ColumnData) ReadLength(reader io.Reader) error {
	n, err := io.ReadFull(reader, column.LengthBuf[:])
	if err2 := base.CheckReadWrite(n, 4, err); err2 != nil {
		return err
	}
	return nil
}

const (
	// NullColumnValue indicates that column has null value without any data
	// https://www.postgresql.org/docs/9.3/static/protocol-message-formats.html
	NullColumnValue int32 = -1
)

// readData read column length and then data from reader
func (column *ColumnData) readData(reader io.Reader, format base.BoundValueFormat) error {
	length := column.Length()
	if int32(length) == NullColumnValue {
		column.data = utils.WrapRawDataAsDecoded(nil)
		column.isNull = true
		return nil
	}
	column.isNull = false
	if length == 0 {
		column.data = utils.WrapRawDataAsDecoded(nil)
		return nil
	}
	data := make([]byte, length)

	// first 4 bytes is packet length and then 2 bytes of column count
	// https://www.postgresql.org/docs/9.3/static/protocol-message-formats.html
	n, err := io.ReadFull(reader, data)
	if err != nil {
		return err
	}
	if format == base.TextFormat {
		column.data, err = utils.DecodeEscaped(data)
		if err != nil && err != utils.ErrDecodeOctalString {
			return err
		}
	} else {
		// do nothing with binary data
		column.data = utils.WrapRawDataAsDecoded(data)
	}

	// ignore utils.ErrDecodeOctalString
	err = nil
	return base.CheckReadWrite(n, length, err)
}

// SetData to column and update LengthBuf with new size
func (column *ColumnData) SetData(newData []byte) {
	column.changed = true
	if column.data == nil {
		column.data = utils.WrapRawDataAsDecoded(newData)
	}
	column.data.Set(newData)
	binary.BigEndian.PutUint32(column.LengthBuf[:], uint32(len(column.data.Encoded())))
}

// parseColumns split whole data row packet into separate columns data
func (packet *PacketHandler) parseColumns(columnFormats []uint16) error {
	packet.columnCount = int(binary.BigEndian.Uint16(packet.descriptionBuf.Bytes()[:2]))

	if packet.columnCount == 0 {
		return nil
	}
	columnReader := bytes.NewReader(packet.descriptionBuf.Bytes()[2:])
	var columns []*ColumnData
	for i := 0; i < packet.columnCount; i++ {
		column := &ColumnData{}
		if err := column.ReadLength(columnReader); err != nil {
			return err
		}
		format, err := GetParameterFormatByIndex(i, columnFormats)
		if err != nil {
			return err
		}
		if err := column.readData(columnReader, format); err != nil {
			return err
		}
		columns = append(columns, column)
	}
	packet.Columns = columns
	return nil
}

// Reset state of handler
func (packet *PacketHandler) Reset() {
	packet.descriptionBuf.Reset()
	packet.dataLength = 0
	packet.columnCount = 0
	packet.Columns = nil
	packet.messageType[0] = 0
}

func (packet *PacketHandler) descriptionBufferCopy() []byte {
	buffer := make([]byte, packet.descriptionBuf.Len())
	copy(buffer, packet.descriptionBuf.Bytes())
	return buffer
}

func (packet *PacketHandler) readMessageType() error {
	n, err := io.ReadFull(packet.reader, packet.messageType[:])
	return base.CheckReadWrite(n, 1, err)
}

// IsDataRow return true if packet has DataRow type
func (packet *PacketHandler) IsDataRow() bool {
	return packet.messageType[0] == DataRowMessageType
}

// IsReadyForQuery returns true if packet has ReadyForQuery type.
func (packet *PacketHandler) IsReadyForQuery() bool {
	return packet.messageType[0] == ReadyForQueryMessageType
}

// IsSimpleQuery return true if packet has SimpleQuery type
func (packet *PacketHandler) IsSimpleQuery() bool {
	return packet.messageType[0] == QueryMessageType
}

// IsParse return true if packet has Parse type
func (packet *PacketHandler) IsParse() bool {
	return packet.messageType[0] == ParseMessageType
}

// IsParseComplete return true if packet has ParseComplete type
func (packet *PacketHandler) IsParseComplete() bool {
	return packet.messageType[0] == ParseCompleteMessageType
}

// IsBind return true if packet has Bind type
func (packet *PacketHandler) IsBind() bool {
	return packet.messageType[0] == BindMessageType
}

// IsBindComplete return true if packet has BindComplete type
func (packet *PacketHandler) IsBindComplete() bool {
	return packet.messageType[0] == BindCompleteMessageType
}

// IsExecute return true if packet has Execute type
func (packet *PacketHandler) IsExecute() bool {
	return packet.messageType[0] == ExecuteMessageType
}

// GetParseData returns parsed Parse packet data.
// Use this only if IsParse() is true.
func (packet *PacketHandler) GetParseData() (*ParsePacket, error) {
	packet.logger.Debugln("GetParseData")
	parse, err := NewParsePacket(packet.descriptionBufferCopy())
	if err != nil {
		packet.logger.Debugln("Failed to parse Parse packet")
		return nil, err
	}
	return parse, nil
}

// GetBindData returns parsed Bind packet data.
// Use this only if IsBind() is true.
func (packet *PacketHandler) GetBindData() (*BindPacket, error) {
	packet.logger.Debugln("GetBindData")
	bind, err := NewBindPacket(packet.descriptionBufferCopy())
	if err != nil {
		packet.logger.Debugln("Failed to parse Bind packet")
		return nil, err
	}
	return bind, nil
}

// GetExecuteData returns parsed Execute packet data.
// Use this only if IsExecute() is true.
func (packet *PacketHandler) GetExecuteData() (*ExecutePacket, error) {
	packet.logger.Debugln("GetExecuteData")
	execute, err := NewExecutePacket(packet.descriptionBufferCopy())
	if err != nil {
		packet.logger.Debugln("Failed to parse Bind packet")
		return nil, err
	}
	return execute, nil
}

// ReplaceQuery query in packet with new query and update packet length
func (packet *PacketHandler) ReplaceQuery(newQuery string) {
	if packet.IsSimpleQuery() {
		packet.descriptionBuf.Reset()
		newQueryLength := len(newQuery) + 1 // query + '0' terminator
		packet.descriptionBuf.Grow(newQueryLength)
		packet.descriptionBuf.Write([]byte(newQuery))
		packet.descriptionBuf.WriteByte(0)
		packet.updatePacketLength(newQueryLength)
	} else if packet.IsParse() {
		packet.logger.Debugln("ReplaceQuery for prepared")
		parse, err := NewParsePacket(packet.descriptionBuf.Bytes())
		if err != nil {
			packet.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantParsePostgresqlParseCommand).WithError(err).Errorln("Can't parse Parse packet")
			return
		}
		parse.ReplaceQuery(newQuery)
		packet.descriptionBuf.Reset()
		packet.descriptionBuf.Grow(parse.Length())
		packet.descriptionBuf.Write(parse.Marshal())
		packet.updatePacketLength(parse.Length())
	}
}

// ReplaceBind update Bind packet with new data, update packet length.
func (packet *PacketHandler) ReplaceBind(bindPacket *BindPacket) error {
	packet.logger.Debugln("ReplaceBind for prepared statement")
	buffer := new(bytes.Buffer)
	n, err := bindPacket.MarshalInto(buffer)
	if err != nil {
		return err
	}
	packet.descriptionBuf = buffer
	packet.updatePacketLength(n)
	return nil
}

// GetSimpleQuery return query value as string from Query packet
func (packet *PacketHandler) GetSimpleQuery() (string, error) {
	return string(packet.descriptionBuf.Bytes()[:packet.dataLength-1]), nil
}

func (packet *PacketHandler) setDataLengthBuffer(dataLengthBuffer []byte) {
	copy(packet.descriptionLengthBuf, dataLengthBuffer)
	// set data length without length itself
	packet.dataLength = int(binary.BigEndian.Uint32(dataLengthBuffer)) - len(dataLengthBuffer)
}

func (packet *PacketHandler) readDataLength() error {
	packet.logger.Debugln("Read data length")
	n, err := io.ReadFull(packet.reader, packet.descriptionLengthBuf)
	if err2 := base.CheckReadWrite(n, len(packet.descriptionLengthBuf), err); err2 != nil {
		return err2
	}
	packet.setDataLengthBuffer(packet.descriptionLengthBuf)
	return nil
}

// readData part of packet
func (packet *PacketHandler) readData(readLength bool) error {
	if readLength {
		if err := packet.readDataLength(); err != nil {
			return err
		}
	}
	packet.descriptionBuf.Grow(packet.dataLength)
	packet.logger.Debugln("Read data")
	nn, err := io.CopyN(packet.descriptionBuf, packet.reader, int64(packet.dataLength))
	return base.CheckReadWrite(int(nn), packet.dataLength, err)
}

// ReadPacket read message type and data part of packet
func (packet *PacketHandler) ReadPacket() error {
	packet.logger.Debugln("Read packet")
	if err := packet.readMessageType(); err != nil {
		return err
	}
	return packet.readData(true)
}

// Constant values of specific postgresql messages - https://www.postgresql.org/docs/current/static/protocol-message-formats.html
var (
	SSLRequest     = []byte{4, 210, 22, 47}
	CancelRequest  = []byte{4, 210, 22, 46}
	StartupRequest = []byte{0, 3, 0, 0}
	GSSENCRequest  = []byte{4, 210, 22, 48}

	// Length is always 8 plus SSLRequest
	SSLRequestHeader = bytes.Join([][]byte{{0x00, 0x00, 0x00, 0x08}, SSLRequest}, []byte{})

	// Length is always 16 plus CancelRequest
	CancelRequestHeader = bytes.Join([][]byte{{0x00, 0x00, 0x00, 0x10}, CancelRequest}, []byte{})

	// Length is always 8 plus GSSENCRequest
	GSSENCRequestHeader = bytes.Join([][]byte{{0x00, 0x00, 0x00, 0x08}, GSSENCRequest}, []byte{})
)

// WithoutMessageType used to indicate that MessageType wasn't set and shouldn't marshaled
const WithoutMessageType = 0

// ErrUnsupportedPacketType error when recognized unsupported message type or new added to postgresql wire protocol
var ErrUnsupportedPacketType = errors.New("unsupported postgresql message type")

// ReadClientPacket read and recognize packets that may be sent only from client/frontend.
//
// There are two types of messages: startup and general ones.
// Due to historical reasons, startup messages have the following format:
//
//     [4-byte length] [4-byte tag] [payload...]
//
// On the other hand, general messages have:
//
//     [1-byte tag] [4-byte length] [payload...]
//
// Overall, as of today (PostgreSQL 14), the protocol supports following packets,
// that can be received from the client (Frontend or F), or both the client and
// the server (Backend) (F&B):
// ```
// | Name                | Type | StartsWith                    |
// |---------------------|------|-------------------------------|
// | Bind                | F    | Byte1('B') || Int32(len)      |
// | CancelRequest       | F    | int32(16)  || Int32(80877102) |
// | Close               | F    | Byte1('C') || Int32(len)      |
// | CopyData            | F&B  | Byte1('d') || Int32(len)      |
// | CopyDone            | F&B  | Byte1('c') || Int32(len)      |
// | CopyFail            | F    | Byte1('f') || Int32(len)      |
// | Describe            | F    | Byte1('D') || Int32(len)      |
// | Execute             | F    | Byte1('E') || Int32(len)      |
// | Flush               | F    | Byte1('H') || Int32(len)      |
// | FunctionCall        | F    | Byte1('F') || Int32(len)      |
// | GSSENCRequest       | F    | Int32(8)   || Int32(80877104) |
// | GSSResponse         | F    | Byte1('p') || Int32(len)      |
// | Parse               | F    | Byte1('P') || Int32(len)      |
// | PasswordMessage     | F    | Byte1('p') || Int32(len)      |
// | Query               | F    | Byte1('Q') || Int32(len)      |
// | SASLInitialResponse | F    | Byte1('p') || Int32(len)      |
// | SASLResponse        | F    | Byte1('p') || Int32(len)      |
// | SSLRequest          | F    | Int32(8)   || Int32(80877103) |
// | StartupMessage      | F    | Int32(len) || Int32(196608)   |
// | Sync                | F    | Byte1('S') || Int32(len)      |
// | Terminate           | F    | Byte1('X') || Int32(len)      |
// ```
//
// Startup message can only be received as first message after connection is
// established. This fact allows to distinguish which format to parse.
// If connection is established, and first message is not startup one, this
// function returns ErrUnsupportedPacketType.
// If startup message is already received, but then comes a message with unknown
// format, it would be parsed as a general message with unknown tag.
//
// https://www.postgresql.org/docs/current/static/protocol-message-formats.html
func (packet *PacketHandler) ReadClientPacket() error {
	if packet.started {
		return packet.readGeneralPacket()
	}
	// https://www.postgresql.org/docs/current/protocol-flow.html
	// First packet should always be StartupMessage/SSLRequest/GSSENCRequest
	return packet.readStartupPacket()
}

// Tries to read one of the startup packets:
// - StartupMessage
// - SSLRequest
// - CancelRequest
// - GSSENCRequest
//
// Due to historical reasons, all startup messages have the following format:
//
//     [4-byte length] [4-byte tag] [payload...]
//
// If the packet cannot be parsed as a startup packets, the ErrUnsupportedPacketType
// is returned.
//
// Source: https://www.postgresql.org/docs/current/protocol-flow.html
func (packet *PacketHandler) readStartupPacket() error {
	packet.Reset()
	// 8 bytes because all startup messages has at least 8 bytes
	packetBuf := make([]byte, 8)
	packet.messageType[0] = WithoutMessageType

	n, err := io.ReadFull(packet.reader, packetBuf)
	if err := base.CheckReadWrite(n, 8, err); err != nil {
		packet.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).WithError(err).Debugln("Can't read 8 bytes of Startup/SSLRequest packet")
		return err
	}

	switch {
	case bytes.Equal(StartupRequest, packetBuf[4:8]):
	case bytes.Equal(SSLRequestHeader, packetBuf[:8]):
	case bytes.Equal(CancelRequestHeader, packetBuf[:8]):
	case bytes.Equal(GSSENCRequestHeader, packetBuf[:8]):
	default:
		return ErrUnsupportedPacketType
	}

	packet.setDataLengthBuffer(packetBuf[:4])

	// We read 8 bytes: 4-byte length and 4-byte tag.
	// Return tag to the descriptionBuf
	n, err = packet.descriptionBuf.Write(packetBuf[4:])
	if err := base.CheckReadWrite(n, 4, err); err != nil {
		return err
	}

	// we read 4 bytes before. decrease before call readData because it read exactly as dataLength
	packet.dataLength -= 4

	if err := packet.readData(false); err != nil {
		return err
	}
	// restore correct value
	packet.dataLength += 4

	packet.started = true

	return nil
}

func (packet *PacketHandler) readGeneralPacket() error {
	packet.Reset()
	// 1-byte id + 4-byte length
	packetBuf := make([]byte, 5)

	n, err := io.ReadFull(packet.reader, packetBuf[:5])
	if err := base.CheckReadWrite(n, 5, err); err != nil {
		packet.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).WithError(err).Debugln("Can't read first 5 bytes")
		return err
	}

	tag := packetBuf[0]

	packet.messageType[0] = tag
	// general message has 4 bytes after first as length
	packet.setDataLengthBuffer(packetBuf[1:5])

	switch tag {
	// Terminate packet
	case 'X':
		packet.terminatePacket = true
		if !bytes.Equal(TerminatePacket, packetBuf[:5]) {
			packet.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlUnexpectedPacket).Warningln("Expected Terminate packet but receive something else")
			return packet.readData(false)
		}
		return nil

	// All known tags
	case 'B', 'C', 'd', 'c', 'f', 'D', 'E', 'H', 'F', 'p', 'P', 'Q', 'S':

	// We don't know the type of message. It may mean that Postgres updated its
	// protocol for example. In any case, produce a warning but try to parse it
	// as general message anyway
	default:
		packet.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlUnexpectedPacket).WithField("packet_buffer", packetBuf).Warningln("Unknown message format. Processed as general message.")
	}

	return packet.readData(false)
}

// Marshal transforms data row into bytes array
// it's not marshal message type if it == 0 (if it was first Startup/SSLRequest packet without message type)
func (packet *PacketHandler) Marshal() ([]byte, error) {
	output := make([]byte, 0, 5+packet.dataLength)
	if packet.messageType[0] != WithoutMessageType {
		output = append(output, packet.messageType[0])
	}
	output = append(output, packet.descriptionLengthBuf...)
	output = append(output, packet.descriptionBuf.Bytes()...)
	return output, nil
}

// IsSSLRequestAllowed returns true server allowed switch to SSL
func (packet *PacketHandler) IsSSLRequestAllowed() bool {
	return packet.messageType[0] == 'S'
}

// IsSSLRequestDeny returns true server denied switch to SSL
func (packet *PacketHandler) IsSSLRequestDeny() bool {
	return packet.messageType[0] == 'N'
}

// SetStarted sets `started` true, which indicates that we should process next
// packets as general ones
func (packet *PacketHandler) SetStarted() {
	packet.started = true
}

// Returns true if startup packet is already received and packet handler excepts
// general messages.
func (packet *PacketHandler) IsAlreadyStarted() bool {
	return packet.started
}
