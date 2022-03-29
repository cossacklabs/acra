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

// Package utils contains various bits and pieces useful as helping functions all over the code.
package utils

import (
	"encoding/binary"
	"fmt"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io"
	"io/ioutil"
	"sync"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"runtime"
)

// WriteFull writes data to io.Writer.
// if wr.Write will return n <= len(data) will
//	sent the rest of data until error or total sent byte count == len(data)
func WriteFull(data []byte, wr io.Writer) (int, error) {
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

// SendData writes length of data block to connection, then writes data itself
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

// ReadDataLength return read data from reader, parsed data length or err
func ReadDataLength(reader io.Reader) ([]byte, int, error) {
	var length [4]byte
	_, err := io.ReadFull(reader, length[:])
	if err != nil {
		return nil, 0, err
	}
	dataSize := int(binary.LittleEndian.Uint32(length[:]))
	return length[:], dataSize, nil
}

// ReadData reads length of data block, then reads data content
// returns data content
func ReadData(reader io.Reader) ([]byte, error) {
	lengthBuf, length, err := ReadDataLength(reader)
	if err != nil {
		return lengthBuf, err
	}
	buf := make([]byte, length)
	_, err = io.ReadFull(reader, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// ReadFile returns contents of file
func ReadFile(path string) ([]byte, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(file)
}

// LoadPublicKey returns contents as PublicKey from keyfile
func LoadPublicKey(path string) (*keys.PublicKey, error) {
	key, err := ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &keys.PublicKey{Value: key}, nil
}

// LoadPrivateKey returns contents as PrivateKey from keyfile
func LoadPrivateKey(path string) (*keys.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	const expectedPerm = os.FileMode(0600)
	if nil == err && runtime.GOOS == "linux" && fi.Mode().Perm() > expectedPerm {
		log.Errorf("Private key file %v has incorrect permissions %s, expected: %s", path, fi.Mode().Perm().String(), expectedPerm.String())
		return nil, fmt.Errorf("private key file %v has incorrect permissions", path)
	}
	key, err := ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &keys.PrivateKey{Value: key}, nil
}

// ZeroizeBytes wipes a byte slice from memory, filling it with zeros.
func ZeroizeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// ZeroizeSymmetricKey wipes a symmetric key from memory, filling it with zero bytes.
func ZeroizeSymmetricKey(key []byte) {
	ZeroizeBytes(key)
}

// ZeroizeSymmetricKeys wipes a symmetric keys from memory, filling it with zero bytes.
func ZeroizeSymmetricKeys(keys [][]byte) {
	for _, key := range keys {
		ZeroizeBytes(key)
	}
}

// ZeroizePrivateKey wipes a private key from memory, filling it with zero bytes.
func ZeroizePrivateKey(privateKey *keys.PrivateKey) {
	if privateKey != nil {
		ZeroizeBytes(privateKey.Value)
	}
}

// ZeroizePrivateKeys wipes a slice of private keys from memory, filling them with zero bytes.
func ZeroizePrivateKeys(privateKeys []*keys.PrivateKey) {
	for _, privateKey := range privateKeys {
		ZeroizePrivateKey(privateKey)
	}
}

// ZeroizeKeyPair wipes a private key of a key pair from memory, filling it with zero bytes.
func ZeroizeKeyPair(keypair *keys.Keypair) {
	if keypair != nil {
		ZeroizePrivateKey(keypair.Private)
	}
}

// FileExists returns true if file exists from path, path can be relative
func FileExists(path string) (bool, error) {
	absPath, err := filepath.Abs(path)
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
	// NotFound indicated not found symbol
	NotFound = -1
)

// Min returns minimum integer out of two
func Min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// GetConfigPathByName returns filepath to config file named "name" from default configs folder
func GetConfigPathByName(name string) string {
	return fmt.Sprintf("configs/%s.yaml", name)
}

// DefaultWaitGroupTimeoutDuration specifies how long should we wait
// for background goroutines finishing while ReaderServer shutdown
const DefaultWaitGroupTimeoutDuration = time.Second

// WaitWithTimeout waits for the waitgroup for the specified max timeout.
// Returns true if waiting timed out.
func WaitWithTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}

// BytesToString converts data to string with re-using same allocated memory
// Warning: data shouldn't be changed after that because it will cause runtime error due to strings are immutable
// Only for read/iterate operations
// See https://groups.google.com/forum/#!msg/Golang-Nuts/ENgbUzYvCuU/90yGx7GUAgAJ .
//
// Note it may break if string and/or slice header will change
// in the future go versions.
func BytesToString(data []byte) string {
	return *(*string)(unsafe.Pointer(&data))
}
