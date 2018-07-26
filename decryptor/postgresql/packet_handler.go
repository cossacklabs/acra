package postgresql

import (
	"bytes"
	"bufio"
	acra_io "github.com/cossacklabs/acra/io"
	"github.com/sirupsen/logrus"
	"encoding/binary"
	"github.com/cossacklabs/acra/decryptor/base"
	"io"
)

type PacketHandler struct {
	firstPacket          bool
	messageType          [1]byte
	descriptionLengthBuf []byte
	descriptionBuf       *bytes.Buffer

	output            []byte
	columnSizePointer []byte
	columnDataBuf     *bytes.Buffer
	writeIndex        int
	columnCount       int
	dataLength        int
	errCh             chan<- error
	reader            *acra_io.ExtendedBufferedReader
	writer            *bufio.Writer
	columnIndex       int
	logger            *logrus.Entry
	Columns           []*ColumnData
}

func NewClientSidePacketHandler(reader *acra_io.ExtendedBufferedReader, writer *bufio.Writer) (*PacketHandler, error) {
	return &PacketHandler{
		columnIndex: 0,
		firstPacket:          true,
		writeIndex:           0,
		output:               nil,
		columnDataBuf:        nil,
		descriptionBuf:       bytes.NewBuffer(make([]byte, OUTPUT_DEFAULT_SIZE)),
		descriptionLengthBuf: make([]byte, 4),
		reader:               reader,
		writer:               writer,
		logger: logrus.WithField("proxy", "client_side"),
	}, nil
}

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

func (packet *PacketHandler) sendMessageType() error{
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

func (packet *PacketHandler) readCount()(int, error){
	// first 4 bytes is packet length and then 2 bytes of column count
	// https://www.postgresql.org/docs/9.3/static/protocol-message-formats.html
	_, err := packet.reader.Read(packet.descriptionBuf.Bytes()[4:6])
	if err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint32(packet.columnSizePointer)), nil
}

type ColumnData struct {
	LengthBuf [4]byte
	Data []byte
}

func (column *ColumnData) Length()int {
	return int(binary.BigEndian.Uint32(column.LengthBuf[:]))
}

func (column *ColumnData) ReadLength(reader io.Reader) error {
	n, err := reader.Read(column.LengthBuf[:])
	if err2 := base.CheckReadWrite(n, 4, err); err2 != nil {
		return err
	}
	return nil
}

func (column *ColumnData) readData(reader io.Reader)error{
	length := column.Length()
	column.Data = make([]byte, length)
	// first 4 bytes is packet length and then 2 bytes of column count
	// https://www.postgresql.org/docs/9.3/static/protocol-message-formats.html
	n, err := reader.Read(column.Data)
	if err2 := base.CheckReadWrite(n, 4, err); err2 != nil {
		return err
	}
	return nil
}

func (packet *PacketHandler) parseColumns() error {
	columnCount := int(binary.BigEndian.Uint16(packet.descriptionBuf.Bytes()[DATA_ROW_LENGTH_BUF_SIZE : DATA_ROW_LENGTH_BUF_SIZE+2]))
	if columnCount == 0 {
		return nil
	}
	columnReader := bytes.NewReader(packet.descriptionBuf.Bytes()[DATA_ROW_LENGTH_BUF_SIZE+2:])
	var columns []*ColumnData
	for i:= 0; i< columnCount; i++{
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
}

func (packet *PacketHandler) Reset() {
	packet.descriptionBuf.Reset()
	packet.columnDataBuf.Reset()
	packet.writeIndex = 0
	packet.dataLength = 0
	packet.columnCount = 0
	packet.columnIndex = 0
	packet.Columns = nil
}
