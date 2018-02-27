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
	"fmt"

	log "github.com/sirupsen/logrus"
	"os"
	"os/user"
	"runtime"
	"strings"
)

const (
	SESSION_DATA_LIMIT = 8 * 1024 // 8 kb
)

var ErrBigDataBlockSize = fmt.Errorf("Block size greater than %v", SESSION_DATA_LIMIT)

func WriteFull(data []byte, wr io.Writer) (int, error) {
	/* write data to io.Writer. if wr.Write will return n <= len(data) will
	sent the rest of data until error or total sent byte count == len(data)
	*/
	sliceCopy := data[:]
	totalSent := 0
	for {
		n, err := wr.Write(sliceCopy)
		if err != nil {
			return 0, err
		}
		totalSent += n
		if totalSent == len(data) {
			return totalSent, nil
		}
		sliceCopy = sliceCopy[totalSent:]
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
	dataSize := int(binary.LittleEndian.Uint32(length[:]))
	buf := make([]byte, dataSize)
	_, err = io.ReadFull(reader, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func AbsPath(path string) (string, error) {
	if len(path) == 0 {
		return path, nil
	}
	if len(path) >= 2 {
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
	}
	return path, nil
}

func ReadFile(path string) ([]byte, error) {
	absPath, err := AbsPath(path)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(file)
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
		log.Errorf("private key file %v has incorrect permissions", path)
		return nil, fmt.Errorf("Error: private key file %v has incorrect permissions", path)
	}
	key, err := ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &keys.PrivateKey{Value: key}, nil
}

func FillSlice(value byte, data []byte) {
	for i := range data {
		data[i] = value
	}
}

func FileExists(path string) (bool, error) {
	absPath, err := AbsPath(path)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(absPath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
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
	halfCount := count / 2
	tag := make([]byte, halfCount)

	for i := 0; i < halfCount; i++ {
		tag[i] = symbol
	}

	for i := 0; i+halfCount <= len(block); i += halfCount {
		if bytes.Equal(tag, block[i:i+halfCount]) {
			start := i
			if i != 0 {
				for ; start > i-halfCount; start-- {
					if block[start-1] != symbol {
						break
					}
				}
			}
			end := i + halfCount - 1
			rightRange := Min(end+halfCount, len(block)-1)
			for ; end < rightRange; end++ {
				if block[end+1] != symbol {
					break
				}
			}

			if count <= (end-start)+1 {
				return start
			}
		}
	}
	return NOT_FOUND
}

func GetConfigPathByName(name string) string {
	return fmt.Sprintf("configs/%s.yaml", name)
}
