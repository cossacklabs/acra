package postgresql

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/sirupsen/logrus"
	"io"
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
		descriptionBuf:       bytes.NewBuffer(make([]byte, OutputDefaultSize)),
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
			packet.descriptionBuf.Write(packet.Columns[i].Data)
		}
		packet.updatePacketLength(newDataLength)
	}
}

// sendPacket marshal packet and send it with writer
func (packet *PacketHandler) sendPacket() error {
	data, err := packet.Marshal()
	if err != nil {
		packet.logger.WithError(err).Errorln("Can't marshal packet")
		return err
	}
	// anyway try to write data that was marshaled even if not full

	if _, err := packet.writer.Write(data); err != nil {
		packet.logger.WithError(err).Debugln("Can't dump marshaled packet")
		return err
	}
	if err := packet.writer.Flush(); err != nil {
		packet.logger.WithError(err).Debugln("Can't flush writer")
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
		packet.logger.WithError(err).Debugln("Can't flush writer")
		return err
	}
	return nil
}

// ColumnData hold column length and data
type ColumnData struct {
	LengthBuf [4]byte
	Data      []byte
	changed   bool
	isNull    bool
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
func (column *ColumnData) readData(reader io.Reader) error {
	length := column.Length()
	if int32(length) == NullColumnValue {
		column.Data = nil
		column.isNull = true
		return nil
	}
	column.isNull = false
	column.Data = make([]byte, length)
	// first 4 bytes is packet length and then 2 bytes of column count
	// https://www.postgresql.org/docs/9.3/static/protocol-message-formats.html
	n, err := io.ReadFull(reader, column.Data)
	return base.CheckReadWrite(n, length, err)
}

// SetData to column and update LengthBuf with new size
func (column *ColumnData) SetData(newData []byte) {
	column.changed = true
	column.Data = newData
	binary.BigEndian.PutUint32(column.LengthBuf[:], uint32(len(newData)))
}

// parseColumns split whole data row packet into separate columns data
func (packet *PacketHandler) parseColumns() error {
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
		if err := column.readData(columnReader); err != nil {
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

func (packet *PacketHandler) readMessageType() error {
	n, err := io.ReadFull(packet.reader, packet.messageType[:])
	return base.CheckReadWrite(n, 1, err)
}

// IsDataRow return true if packet has DataRow type
func (packet *PacketHandler) IsDataRow() bool {
	return packet.messageType[0] == DataRowMessageType
}

// IsSimpleQuery return true if packet has SimpleQuery type
func (packet *PacketHandler) IsSimpleQuery() bool {
	return packet.messageType[0] == QueryMessageType
}

// IsParse return true if packet has Parse type
func (packet *PacketHandler) IsParse() bool {
	return packet.messageType[0] == ParseMessageType
}

//GetParseQuery return query string from Parse packet or error
func (packet *PacketHandler) GetParseQuery() (string, error) {
	packet.logger.Debugln("GetParseQuery")
	parse, err := NewParsePacket(packet.descriptionBuf.Bytes())
	if err != nil {
		packet.logger.Debugln("GetParseQuery error")
		return "", err
	}
	return parse.QueryString(), nil
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
			packet.logger.WithError(err).Errorln("Can't parse Parse packet")
			return
		}
		parse.ReplaceQuery(newQuery)
		packet.descriptionBuf.Reset()
		packet.descriptionBuf.Grow(parse.Length())
		packet.descriptionBuf.Write(parse.Marshal())
		packet.updatePacketLength(parse.Length())
	}
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
)

// WithoutMessageType used to indicate that MessageType wasn't set and shouldn't marshaled
const WithoutMessageType = 0

// ErrUnsupportedPacketType error when recognized unsupported message type or new added to postgresql wire protocol
var ErrUnsupportedPacketType = errors.New("unsupported postgresql message type")

// ReadClientPacket read and recognize packets that may be sent only from client/frontend. It's all message types marked
// with (F) or (F/B) on https://www.postgresql.org/docs/current/static/protocol-message-formats.html
func (packet *PacketHandler) ReadClientPacket() error {
	packet.Reset()
	// 8 bytes because startup/ssl/cancel messages has at least 8 bytes
	packetBuf := make([]byte, 8)
	packet.messageType[0] = WithoutMessageType
	// any message has at least 5 bytes: TypeOfMessage(1) + Length(4) or 8 bytes of special messages

	n, err := io.ReadFull(packet.reader, packetBuf[:5])
	if err := base.CheckReadWrite(n, 5, err); err != nil {
		packet.logger.WithError(err).Debugln("Can't read first 5 bytes")
		return err
	}
	/*
		Postgresql has 3 messages that hasn't general message format <MessageType> + <Message Length>. It's ssl request, cancelation and startup message
		General message has at least 5 bytes in packet, these 3 packets has at least 8 bytes (<Message Length> + <Constant Value>)
		We read first 5 bytes, check is there known message types. If not then we try to read 3 more bytes and recognize 3 special messages
		by their values. If we don't recognize, then process it as general message. We may have error if it's unknown message with message length < 8 bytes when
		we not recognize, try to read +3 bytes and will block on system call read to read more when message may have only 1 bytes of MessageType and minimal MessageLength = 4 bytes (itself)
	*/
	switch packetBuf[0] {
	// all known message types with flags (F) or (F/B) on https://www.postgresql.org/docs/current/static/protocol-message-formats.html
	case 'S', 'p', 'F', 'H', 'E', 'D', 'f', 'c', 'd', 'C', 'B', 'Q', 'P':
		// set message type
		packet.messageType[0] = packetBuf[0]
		// general message has 4 bytes after first as length
		packet.setDataLengthBuffer(packetBuf[1:5])
		return packet.readData(false)
	case TerminatePacket[0]:
		// set message type
		packet.messageType[0] = packetBuf[0]
		// general message has 4 bytes after first as length
		packet.setDataLengthBuffer(packetBuf[1:5])
		packet.terminatePacket = true
		if !bytes.Equal(TerminatePacket, packetBuf[:5]) {
			packet.logger.Warningln("Expected Terminate packet but receive something else")
			return packet.readData(false)
		}
		return nil
	default:
		// fill our buf with other 3 bytes to check is it special message
		n, err := io.ReadFull(packet.reader, packetBuf[5:])
		if err := base.CheckReadWrite(n, 3, err); err != nil {
			return err
		}
		// write packet data to correct buf
		n, err = packet.descriptionBuf.Write(packetBuf[4:])
		if err := base.CheckReadWrite(n, 4, err); err != nil {
			return err
		}
		packet.setDataLengthBuffer(packetBuf[:4])

		// ssl and cancel requests have known and different lengths (8 and 16 respectively) or variable-length in startup request
		switch packetBuf[3] {
		// ssl/cancel requests
		case 8, 16:
			// ssl/cancel request has 8 byte length and 5 bytes we already read
			if bytes.Equal(SSLRequest, packetBuf[4:]) {
				return nil
			} else if bytes.Equal(CancelRequest, packetBuf[4:]) {
				return nil
			}
			return ErrUnsupportedPacketType
		// startup request or unknown message type
		default:
			if !bytes.Equal(StartupRequest, packetBuf[4:]) {
				packet.logger.WithField("packet_buffer", packetBuf).Warningln("Expected startup message. Process as general message.")
				// we took unknown message type that wasn't recognized on top case and it's not special messages startup/ssl/cancel
				// so we process it as general message type which has first byte as type and next 4 bytes is length of message
				// above we read 8 bytes as for special messages, so we need to read dataLength -3 bytes
				packet.messageType[0] = packetBuf[0]
				packet.setDataLengthBuffer(packetBuf[1:5])
				packet.descriptionBuf.Reset()
				packet.descriptionBuf.Write(packetBuf[5:])
				packet.dataLength -= 3
				if err := packet.readData(false); err != nil {
					return err
				}
				packet.dataLength += 3
				return nil
			}

			// we read 4 bytes before. decrease before call readData because it read exactly as dataLength
			packet.dataLength -= 4

			if err := packet.readData(false); err != nil {
				return err
			}
			// restore correct value
			packet.dataLength += 4
			return nil
		}
	}
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
