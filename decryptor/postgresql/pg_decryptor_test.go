package postgresql

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"github.com/sirupsen/logrus"
	"testing"
)

func TestDataRowLastEmptyColumn(t *testing.T) {
	// data row packet hex dump with 5 columns and last column has length 0
	// check correct processing when last column has length 0 and packetHandler doesn't try to read from connection
	// and doesn't take io.EOF after this
	data, err := hex.DecodeString("44000001f50005000000013100000006686f746a61720000000131000001d33c212d2d20486f746a617220547261636b696e6720436f646520666f7220636f737361636b6c6162732e636f6d202d2d3e0d0a3c7363726970743e0d0a202020202866756e6374696f6e28682c6f2c742c6a2c612c72297b0d0a2020202020202020682e686a3d682e686a7c7c66756e6374696f6e28297b28682e686a2e713d682e686a2e717c7c5b5d292e7075736828617267756d656e7473297d3b0d0a2020202020202020682e5f686a53657474696e67733d7b686a69643a313137373730362c686a73763a367d3b0d0a2020202020202020613d6f2e676574456c656d656e747342795461674e616d6528276865616427295b305d3b0d0a2020202020202020723d6f2e637265617465456c656d656e74282773637269707427293b722e6173796e633d313b0d0a2020202020202020722e7372633d742b682e5f686a53657474696e67732e686a69642b6a2b682e5f686a53657474696e67732e686a73763b0d0a2020202020202020612e617070656e644368696c642872293b0d0a202020207d292877696e646f772c646f63756d656e742c2768747470733a2f2f7374617469632e686f746a61722e636f6d2f632f686f746a61722d272c272e6a733f73763d27293b0d0a3c2f7363726970743e00000000")
	if err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(data)
	writerBuf := bytes.NewBuffer(make([]byte, len(data)))
	writer := bufio.NewWriter(writerBuf)
	packetHandler, err := NewDbSidePacketHandler(reader, writer, logrus.NewEntry(logrus.New()))
	if err != nil {
		t.Fatal(err)
	}
	if err := packetHandler.ReadPacket(); err != nil {
		t.Fatal(err)
	}

	if !packetHandler.IsDataRow() {
		t.Fatal("Must be data row")
	}

	if err := packetHandler.parseColumns(); err != nil {
		t.Fatal(err)
	}

}
