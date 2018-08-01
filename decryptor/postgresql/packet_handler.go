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

	columnCount int
	dataLength  int
	reader      io.Reader
	writer      *bufio.Writer
	logger      *logrus.Entry
	Columns     []*ColumnData
}

// NewClientSidePacketHandler return new PacketHandler with initialized own logger for client's packets
func NewClientSidePacketHandler(reader io.Reader, writer *bufio.Writer) (*PacketHandler, error) {
	return &PacketHandler{
		descriptionBuf:       bytes.NewBuffer(make([]byte, OutputDefaultSize)),
		descriptionLengthBuf: make([]byte, 4),
		reader:               reader,
		writer:               writer,
		logger:               logrus.WithField("proxy", "client_side"),
	}, nil
}

// NewClientSidePacketHandler return new PacketHandler with initialized own logger for databases's packets
func NewDbSidePacketHandler(reader io.Reader, writer *bufio.Writer) (*PacketHandler, error) {
	return &PacketHandler{
		descriptionBuf:       bytes.NewBuffer(make([]byte, OutputDefaultSize)),
		descriptionLengthBuf: make([]byte, 4),
		reader:               reader,
		writer:               writer,
		logger:               logrus.WithField("proxy", "db_side"),
	}, nil
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
		// update packet size
		binary.BigEndian.PutUint32(packet.descriptionLengthBuf[:], uint32(newDataLength+DataRowLengthBufSize))
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
		packet.logger.WithError(err).Errorln("Can't dump marshaled packet")
		return err
	}
	if err := packet.writer.Flush(); err != nil {
		packet.logger.WithError(err).Errorln("Can't flush writer")
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
		packet.logger.WithError(err).Errorln("Can't flush writer")
		return err
	}
	return nil
}

// ColumnData hold column length and data
type ColumnData struct {
	LengthBuf [4]byte
	Data      []byte
	changed   bool
}

// Length return column length converted from LengthBuf
func (column *ColumnData) Length() int {
	return int(binary.BigEndian.Uint32(column.LengthBuf[:]))
}

// ReadLength of column
func (column *ColumnData) ReadLength(reader io.Reader) error {
	n, err := reader.Read(column.LengthBuf[:])
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
		return nil
	}
	column.Data = make([]byte, length)
	// first 4 bytes is packet length and then 2 bytes of column count
	// https://www.postgresql.org/docs/9.3/static/protocol-message-formats.html
	n, err := reader.Read(column.Data)
	if err2 := base.CheckReadWrite(n, length, err); err2 != nil {
		return err
	}
	return nil
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
	n, err := packet.reader.Read(packet.messageType[:])
	if err := base.CheckReadWrite(n, 1, err); err != nil {
		return err
	}
	return nil
}

// IsDataRow return true if packet has DataRow type
func (packet *PacketHandler) IsDataRow() bool {
	return packet.messageType[0] == DataRowMessageType
}

// IsSimpleQuery return true if packet has SimpleQuery type
func (packet *PacketHandler) IsSimpleQuery() bool {
	return packet.messageType[0] == QueryMessageType
}

// ErrShortRead error during reading
var ErrShortRead = errors.New("read less bytes than expected")

// readData part of packet
func (packet *PacketHandler) readData() error {
	packet.logger.Debugln("Read data length")
	n, err := packet.reader.Read(packet.descriptionLengthBuf)
	if err != nil {
		return err
	}
	if n != len(packet.descriptionLengthBuf) {
		return ErrShortRead
	}
	packet.dataLength = int(binary.BigEndian.Uint32(packet.descriptionLengthBuf)) - len(packet.descriptionLengthBuf)
	packet.descriptionBuf.Reset()
	packet.descriptionBuf.Grow(packet.dataLength)
	packet.logger.Debugln("Read data")
	nn, err := io.CopyN(packet.descriptionBuf, packet.reader, int64(packet.dataLength))
	if err != nil {
		return err
	}
	if nn != int64(packet.dataLength) {
		return ErrShortRead
	}
	return nil
}

// ReadPacket read message type and data part of packet
func (packet *PacketHandler) ReadPacket() error {
	packet.logger.Debugln("Read packet")
	if err := packet.readMessageType(); err != nil {
		return err
	}
	return packet.readData()
}

// Marshal transforms data row into bytes array
// it's not marshal message type if it == 0 (if it was first Startup/SSLRequest packet without message type)
func (packet *PacketHandler) Marshal() ([]byte, error) {
	output := make([]byte, 0, 5+packet.dataLength)
	if packet.messageType[0] != 0 {
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
