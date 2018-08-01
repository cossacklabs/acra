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

// Package io provides useful functions with io operations, used by most of Acra components,
// like BufferedReader that reads data from buffer.
package io

import (
	"bufio"
	"io"
)

// ExtendedBufferedReader extend bufio.Reader.Read method
type ExtendedBufferedReader struct {
	reader *bufio.Reader
}

// NewExtendedBufferedReader return new ExtendedBufferedReader
func NewExtendedBufferedReader(reader *bufio.Reader) *ExtendedBufferedReader {
	return &ExtendedBufferedReader{reader: reader}
}

// Read until buf full or return error
// when postgresql return a lot of data it will return as sequence of packets
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

// Buffered returns the number of bytes that can be read from the current buffer.
func (r *ExtendedBufferedReader) Buffered() int {
	return r.reader.Buffered()
}

// Peek returns the next n bytes without advancing the reader. The bytes stop
// being valid at the next read call. If Peek returns fewer than n bytes, it
// also returns an error explaining why the read is short. The error is
// ErrBufferFull if n is larger than b's buffer size.
func (r *ExtendedBufferedReader) Peek(n int) ([]byte, error) {
	return r.reader.Peek(n)
}

// ReadByte reads and returns a single byte.
// If no byte is available, returns an error.
func (r *ExtendedBufferedReader) ReadByte() (byte, error) {
	return r.reader.ReadByte()
}

// ReadBytes reads until the first occurrence of delim in the input,
// returning a slice containing the data up to and including the delimiter.
// If ReadBytes encounters an error before finding a delimiter,
// it returns the data read before the error and the error itself (often io.EOF).
// ReadBytes returns err != nil if and only if the returned data does not end in
// delim.
// For simple uses, a Scanner may be more convenient.
func (r *ExtendedBufferedReader) ReadBytes(delim byte) ([]byte, error) {
	return r.reader.ReadBytes(delim)
}

// Reset discards any buffered data, resets all state, and switches
// the buffered reader to read from r.
func (r *ExtendedBufferedReader) Reset(reader io.Reader) {
	r.reader.Reset(reader)
}

// UnreadByte unreads the last byte. Only the most recently read byte can be unread.
func (r *ExtendedBufferedReader) UnreadByte() error {
	return r.reader.UnreadByte()
}

// WriteTo implements io.WriterTo.
func (r *ExtendedBufferedReader) WriteTo(w io.Writer) (n int64, err error) {
	return r.reader.WriteTo(w)
}
