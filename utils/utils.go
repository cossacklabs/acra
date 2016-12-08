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
package utils

import (
	"encoding/binary"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io"
	"io/ioutil"

	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/user"
	"runtime"
	"strings"
)

func WriteFull(data []byte, wr io.Writer) (int, error) {
	/* write data to io.Writer. if wr.Write will return n <= len(data) will
	sent the rest of data until error or total sent byte count == len(data)
	*/
	slice_copy := data[:]
	total_sent := 0
	for {
		n, err := wr.Write(slice_copy)
		if err != nil {
			return 0, err
		}
		total_sent += n
		if total_sent == len(data) {
			return total_sent, nil
		}
		slice_copy = slice_copy[total_sent:]
	}
}

func SendData(data []byte, conn io.Writer) error {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(len(data)))
	_, err := WriteFull(buf[:], conn)
	if err != nil {
		return err
	}
	_, err = WriteFull(data, conn)
	if err != nil {
		return err
	}
	return nil
}

func ReadData(reader io.Reader) ([]byte, error) {
	var length [4]byte
	_, err := io.ReadFull(reader, length[:])
	if err != nil {
		return nil, err
	}
	data_size := int(binary.LittleEndian.Uint32(length[:]))
	buf := make([]byte, data_size)
	_, err = io.ReadFull(reader, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func AbsPath(path string) (string, error) {
	if path[:2] == "~/" {
		usr, err := user.Current()
		if err != nil {
			return path, err
		}
		dir := usr.HomeDir
		path = strings.Replace(path, "~", dir, 1)
		return path, nil
	} else if path[:2] == "./" {
		workdir, err := os.Getwd()
		if err != nil {
			return path, err
		}
		path = strings.Replace(path, ".", workdir, 1)
		return path, nil
	}
	return path, nil
}

func ReadFile(path string) ([]byte, error) {
	abs_path, err := AbsPath(path)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(abs_path)
	if err != nil {
		return nil, err
	}
	key, err := ioutil.ReadAll(file)
	return key, nil
}

func LoadPublicKey(path string) (*keys.PublicKey, error) {
	key, err := ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &keys.PublicKey{Value: key}, nil
}

func LoadPrivateKey(path string) (*keys.PrivateKey, error) {
	fi, err := os.Stat(path)
	if nil == err && runtime.GOOS == "linux" && fi.Mode().Perm().String() != "-rw-------" && fi.Mode().Perm().String() != "-r--------" {
		log.Printf("Error: private key file %v has incorrect permissions", path)
		return nil, errors.New(fmt.Sprintf("Error: private key file %v has incorrect permissions", path))
	}
	key, err := ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &keys.PrivateKey{Value: key}, nil
}

func FillSlice(value byte, data []byte) {
	for i, _ := range data {
		data[i] = value
	}
}

func FileExists(path string) (bool, error) {
	abs_path, err := AbsPath(path)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(abs_path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		} else {
			return false, err
		}
	}
	return true, nil
}

const (
	NOT_FOUND = -1
)

func Min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
func FindTag(symbol byte, count int, block []byte) int {
	if len(block) < count {
		return NOT_FOUND
	}
	half_count := count / 2
	tag := make([]byte, half_count)

	for i := 0; i < half_count; i++ {
		tag[i] = symbol
	}

	for i := 0; i+half_count <= len(block); i += half_count {
		if bytes.Equal(tag, block[i:i+half_count]) {
			start := i
			if i != 0 {
				for ; start > i-half_count; start-- {
					if block[start-1] != symbol {
						break
					}
				}
			}
			end := i + half_count - 1
			right_range := Min(end+half_count, len(block)-1)
			for ; end < right_range; end++ {
				if block[end+1] != symbol {
					break
				}
			}

			if count == (end-start)+1 {
				return start
			}
		}
	}
	return NOT_FOUND
}
