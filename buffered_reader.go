package acra

import (
	"bufio"
	"io"
)

/* extend bufio.Reader.Read */
type ExtendedBufferedReader struct {
	reader *bufio.Reader
}

/* Read until buf full or return error
when postgresql return a lot of data he will return as sequence of packets */
func (r *ExtendedBufferedReader) Read(buf []byte) (int, error) {
	n, err := r.reader.Read(buf)
	if err != nil {
		return n, err
	}
	if n != len(buf) {
		count := n
		for count != len(buf) {
			n, err = r.reader.Read(buf[count:])
			count += n
			if err != nil {
				return count + n, err
			}
			if count == len(buf) {
				return count, nil
			}
		}
	}
	return n, nil
}
func (r *ExtendedBufferedReader) Buffered() int {
	return r.reader.Buffered()
}
func (r *ExtendedBufferedReader) Discard(n int) (discarded int, err error) {
	return r.reader.Discard(n)
}
func (r *ExtendedBufferedReader) Peek(n int) ([]byte, error) {
	return r.reader.Peek(n)
}
func (r *ExtendedBufferedReader) ReadByte() (byte, error) {
	return r.reader.ReadByte()
}
func (r *ExtendedBufferedReader) ReadBytes(delim byte) ([]byte, error) {
	return r.reader.ReadBytes(delim)
}
func (r *ExtendedBufferedReader) Reset(reader io.Reader) {
	r.reader.Reset(reader)
}
func (r *ExtendedBufferedReader) UnreadByte() error {
	return r.reader.UnreadByte()
}
func (r *ExtendedBufferedReader) WriteTo(w io.Writer) (n int64, err error) {
	return r.reader.WriteTo(w)
}
