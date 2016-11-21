package acra

type BinaryByteReader struct{}

func NewBinaryByteReader() *BinaryByteReader {
	return &BinaryByteReader{}
}

func (reader *BinaryByteReader) GetBuffered() []byte {
	return []byte{}
}

func (reader *BinaryByteReader) Reset() {}

func (reader *BinaryByteReader) ReadByte(c byte) (bool, byte, error) {
	return true, c, nil
}
