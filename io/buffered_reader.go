// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package io

import (
	"bufio"
	"io"
)

/* extend bufio.Reader.Read */
type ExtendedBufferedReader struct {
	reader *bufio.Reader
}

func NewExtendedBufferedReader(reader *bufio.Reader) *ExtendedBufferedReader {
	return &ExtendedBufferedReader{reader: reader}
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
