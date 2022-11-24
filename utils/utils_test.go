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
package utils

import (
	"bytes"
	"crypto/rand"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/stretchr/testify/assert"
	"os"
	"reflect"
	"testing"
	"unsafe"
)

func TestFileExists(t *testing.T) {
	testPath := "/tmp/testfilepath"
	exists, err := FileExists(testPath)
	if exists || err != nil {
		t.Fatalf("File exists or returned any error. err = %v\n", err)
	}
	_, err = os.Create(testPath)
	defer os.Remove(testPath)
	if err != nil {
		t.Fatalf("can't create test temporary file %v. err - %v\n", testPath, err)
	}
	exists, err = FileExists(testPath)
	if !exists || err != nil {
		t.Fatalf("File not exists or returned any error. err = %v\n", err)
	}
}

func TestZeroizeSymmetricKey(t *testing.T) {
	symKey := make([]byte, 32)
	allZeros := make([]byte, 32)
	rand.Read(symKey)

	ZeroizeSymmetricKey(symKey)

	if !bytes.Equal(symKey, allZeros) {
		t.Error("symmetrick key not zeroized")
	}
}

func TestZeroizeNilSymmetricKey(t *testing.T) {
	ZeroizeSymmetricKey(nil) // no panic
}

func TestZeroizePrivateKey(t *testing.T) {
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatalf("failed to generated key pair: %v", err)
	}
	allZeros := make([]byte, len(keypair.Private.Value))

	ZeroizePrivateKey(keypair.Private)

	if !bytes.Equal(keypair.Private.Value, allZeros) {
		t.Error("private key not zeroized")
	}
}

func TestZeroizeNilPrivateKey(t *testing.T) {
	ZeroizePrivateKey(nil) // no panic
	ZeroizePrivateKey(&keys.PrivateKey{})
}

func TestZeroizeKeyPair(t *testing.T) {
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatalf("failed to generated key pair: %v", err)
	}
	allZeros := make([]byte, len(keypair.Private.Value))
	oldPublicValue := make([]byte, len(keypair.Public.Value))
	copy(oldPublicValue, keypair.Public.Value)

	ZeroizeKeyPair(keypair)

	if !bytes.Equal(keypair.Private.Value, allZeros) {
		t.Error("private key not zeroized")
	}
	if !bytes.Equal(keypair.Public.Value, oldPublicValue) {
		t.Error("public key has changed")
	}
}

func TestZeroizeNilKeyPair(t *testing.T) {
	ZeroizeKeyPair(nil) // no panic
	ZeroizeKeyPair(&keys.Keypair{})
}

func TestBytesToString(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"nil array", args{nil}, ""},
		{"empty array", args{[]byte{}}, ""},
		{"empty array", args{[]byte(`some data`)}, `some data`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BytesToString(tt.args.data)
			if got != tt.want {
				t.Errorf("BytesToString() = %v, want %v", got, tt.want)
			}
			byteHeader := (*reflect.SliceHeader)(unsafe.Pointer(&tt.args.data))
			strHeader := (*reflect.StringHeader)(unsafe.Pointer(&got))
			if byteHeader.Len == 0 {
				return
			}
			if byteHeader.Data != strHeader.Data {
				t.Fatal("Result string uses another block of memory")
			}
		})
	}
}

func TestGetNRunesAsBytes(t *testing.T) {
	type testcase struct {
		in         string
		out        []byte
		runeLength int
		outLength  int
	}
	testcases := []testcase{
		// each cyrillic symbol represented as 2 bytes
		{`ыіґtest`, []byte{209, 139, 209, 150, 210, 145}, 3, 6},
		{`test`, []byte{'t', 'e', 's'}, 3, 3},
	}
	for _, tcase := range testcases {
		out := GetNRunesAsBytes(tcase.in, tcase.runeLength)
		assert.Equal(t, out, tcase.out)
		assert.Equal(t, len(out), tcase.outLength)
	}
}
